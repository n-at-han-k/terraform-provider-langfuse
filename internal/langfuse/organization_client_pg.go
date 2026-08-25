package langfuse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lucsky/cuid"
)

// organizationClientPG implements OrganizationClient against Postgres.
//
// Over HTTP the public/private key pair was a Basic-auth credential, and
// authenticating with it is what scoped every call to one organization. There
// is nothing to authenticate to here, so the public key is used as a LOOKUP
// instead -- it selects the api_keys row, which names the organization. The HCL
// surface is unchanged as a result.
//
// The private key is deliberately unused. Verifying it against its bcrypt hash
// would cost a KDF round per call and prove nothing: anyone who can reach this
// database can read and write every row in it regardless. It stays in the
// signature so the interface and the resource schemas do not change.
type organizationClientPG struct {
	pool      *pgxpool.Pool
	salt      string
	publicKey string

	// Resolved once per client and reused; a Terraform run makes many calls
	// through the same client and the mapping cannot change underneath it.
	once  sync.Once
	orgID string
	orgErr error
}

func NewOrganizationClientPG(pool *pgxpool.Pool, salt, publicKey, privateKey string) OrganizationClient {
	return &organizationClientPG{pool: pool, salt: salt, publicKey: publicKey}
}

// organizationID maps the configured public key to the organization it belongs
// to. A key that is missing, or that is project-scoped rather than
// organization-scoped, is a configuration error worth naming precisely -- it is
// otherwise diagnosed as a puzzling "organization not found".
func (c *organizationClientPG) organizationID(ctx context.Context) (string, error) {
	c.once.Do(func() {
		if c.publicKey == "" {
			c.orgErr = fmt.Errorf("organization_public_key is required to identify the organization")
			return
		}

		var orgID *string
		err := c.pool.QueryRow(ctx, `
			SELECT organization_id FROM api_keys
			 WHERE public_key = $1 AND scope = 'ORGANIZATION'`,
			c.publicKey).Scan(&orgID)
		if errors.Is(err, pgx.ErrNoRows) {
			c.orgErr = fmt.Errorf("no organization-scoped API key matches the configured organization_public_key; create one with langfuse_organization_api_key")
			return
		}
		if err != nil {
			c.orgErr = fmt.Errorf("failed to resolve organization from API key: %w", err)
			return
		}
		if orgID == nil {
			c.orgErr = fmt.Errorf("the API key matching organization_public_key has no organization; it may be a project-scoped key")
			return
		}
		c.orgID = *orgID
	})

	return c.orgID, c.orgErr
}

// -- projects -----------------------------------------------------------------

// Langfuse SOFT-deletes projects: the row stays and deleted_at is stamped. Every
// read here filters them out, or a deleted project would keep satisfying reads
// and Terraform would never converge on recreating it.
const projectColumns = `id, name, COALESCE(retention_days, 0), metadata`

func scanProject(row pgx.Row) (*Project, error) {
	var (
		project  Project
		metadata []byte
	)
	if err := row.Scan(&project.ID, &project.Name, &project.RetentionDays, &metadata); err != nil {
		return nil, err
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &project.Metadata); err != nil {
			return nil, fmt.Errorf("failed to decode project metadata: %w", err)
		}
	}
	return &project, nil
}

func (c *organizationClientPG) ListProjects(ctx context.Context) ([]*Project, error) {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := c.pool.Query(ctx, `
		SELECT `+projectColumns+` FROM projects
		 WHERE org_id = $1 AND deleted_at IS NULL
		 ORDER BY created_at`, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	defer rows.Close()

	var projects []*Project
	for rows.Next() {
		project, err := scanProject(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to read project: %w", err)
		}
		projects = append(projects, project)
	}
	return projects, rows.Err()
}

func (c *organizationClientPG) GetProject(ctx context.Context, projectID string) (*Project, error) {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return nil, err
	}

	project, err := scanProject(c.pool.QueryRow(ctx, `
		SELECT `+projectColumns+` FROM projects
		 WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`, projectID, orgID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("project %s not found", projectID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get project %s: %w", projectID, err)
	}
	return project, nil
}

func (c *organizationClientPG) CreateProject(ctx context.Context, request *CreateProjectRequest) (*Project, error) {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return nil, err
	}
	metadata, err := marshalMetadata(request.Metadata)
	if err != nil {
		return nil, err
	}

	project, err := scanProject(c.pool.QueryRow(ctx, `
		INSERT INTO projects (id, name, org_id, retention_days, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		RETURNING `+projectColumns,
		cuid.New(), request.Name, orgID, nullableRetention(request.RetentionDays), metadata))
	if err != nil {
		return nil, fmt.Errorf("failed to create project %q: %w", request.Name, err)
	}
	return project, nil
}

func (c *organizationClientPG) UpdateProject(ctx context.Context, projectID string, request *UpdateProjectRequest) (*Project, error) {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return nil, err
	}
	metadata, err := marshalMetadata(request.Metadata)
	if err != nil {
		return nil, err
	}

	project, err := scanProject(c.pool.QueryRow(ctx, `
		UPDATE projects
		   SET name = $3, retention_days = $4, metadata = $5, updated_at = CURRENT_TIMESTAMP
		 WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
		RETURNING `+projectColumns,
		projectID, orgID, request.Name, nullableRetention(request.RetentionDays), metadata))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("project %s not found", projectID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update project %s: %w", projectID, err)
	}
	return project, nil
}

// DeleteProject soft-deletes, matching what Langfuse's own delete does. A hard
// DELETE would cascade into every trace, observation and score the project owns
// -- an irreversible amount of data for a `terraform destroy` to remove without
// the application's own cleanup path having run.
func (c *organizationClientPG) DeleteProject(ctx context.Context, projectID string) error {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return err
	}

	_, err = c.pool.Exec(ctx, `
		UPDATE projects SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		 WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL`, projectID, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete project %s: %w", projectID, err)
	}
	return nil
}

// retention_days is nullable and Langfuse treats NULL as "no retention limit";
// the interface carries a plain int32, so zero is mapped back onto NULL.
func nullableRetention(days int32) any {
	if days <= 0 {
		return nil
	}
	return days
}

// -- project API keys ---------------------------------------------------------

func (c *organizationClientPG) GetProjectApiKey(ctx context.Context, projectID string, apiKeyID string) (*ProjectApiKey, error) {
	if _, err := c.GetProject(ctx, projectID); err != nil {
		return nil, err
	}

	var key ProjectApiKey
	err := c.pool.QueryRow(ctx, `
		SELECT id, public_key, note FROM api_keys
		 WHERE id = $1 AND project_id = $2 AND scope = 'PROJECT'`,
		apiKeyID, projectID).Scan(&key.ID, &key.PublicKey, &key.Note)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("cannot find API key with ID %s in project %s", apiKeyID, projectID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API key %s: %w", apiKeyID, err)
	}
	return &key, nil
}

func (c *organizationClientPG) CreateProjectApiKey(ctx context.Context, projectID string, request *CreateProjectApiKeyRequest) (*ProjectApiKey, error) {
	if _, err := c.GetProject(ctx, projectID); err != nil {
		return nil, err
	}

	material, err := newAPIKeyMaterial(c.salt)
	if err != nil {
		return nil, err
	}

	var note *string
	if request != nil {
		note = request.Note
	}

	id := cuid.New()
	_, err = c.pool.Exec(ctx, `
		INSERT INTO api_keys (
			id, created_at, note, public_key, hashed_secret_key,
			display_secret_key, fast_hashed_secret_key,
			project_id, organization_id, scope
		) VALUES ($1, CURRENT_TIMESTAMP, $2, $3, $4, $5, $6, $7, NULL, 'PROJECT')`,
		id, note, material.PublicKey, material.HashedSecretKey,
		material.DisplaySecretKey, material.FastHashedSecretKey, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key for project %s: %w", projectID, err)
	}

	return &ProjectApiKey{
		ID:        id,
		PublicKey: material.PublicKey,
		SecretKey: material.SecretKey,
		Note:      note,
	}, nil
}

func (c *organizationClientPG) DeleteProjectApiKey(ctx context.Context, projectID string, apiKeyID string) error {
	_, err := c.pool.Exec(ctx, `
		DELETE FROM api_keys WHERE id = $1 AND project_id = $2 AND scope = 'PROJECT'`,
		apiKeyID, projectID)
	if err != nil {
		return fmt.Errorf("failed to delete API key %s in project %s: %w", apiKeyID, projectID, err)
	}
	return nil
}

// -- organization memberships -------------------------------------------------

// Memberships read straight out of the table are always live; the HTTP API's
// "status" distinguished those from pending invitations, which live in a
// separate table and are not modelled here.
const membershipStatusActive = "ACTIVE"

func (c *organizationClientPG) ListMemberships(ctx context.Context) ([]OrganizationMembership, error) {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := c.pool.Query(ctx, `
		SELECT m.id, COALESCE(u.email, ''), m.role::text, m.user_id, COALESCE(u.name, '')
		  FROM organization_memberships m
		  JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1
		 ORDER BY m.created_at`, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships: %w", err)
	}
	defer rows.Close()

	var memberships []OrganizationMembership
	for rows.Next() {
		m := OrganizationMembership{Status: membershipStatusActive}
		if err := rows.Scan(&m.ID, &m.Email, &m.Role, &m.UserID, &m.Username); err != nil {
			return nil, fmt.Errorf("failed to read membership: %w", err)
		}
		memberships = append(memberships, m)
	}
	return memberships, rows.Err()
}

// GetMembership accepts either a membership id or a user id.
//
// The resource layer stores whichever of the two the create path happened to
// produce -- it falls back to the user id when the API omits the membership id
// -- so both have to resolve here or Read() would drop valid resources.
func (c *organizationClientPG) GetMembership(ctx context.Context, membershipID string) (*OrganizationMembership, error) {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return nil, err
	}

	m := OrganizationMembership{Status: membershipStatusActive}
	err = c.pool.QueryRow(ctx, `
		SELECT m.id, COALESCE(u.email, ''), m.role::text, m.user_id, COALESCE(u.name, '')
		  FROM organization_memberships m
		  JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1 AND (m.id = $2 OR m.user_id = $2)`,
		orgID, membershipID).Scan(&m.ID, &m.Email, &m.Role, &m.UserID, &m.Username)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMembershipNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get membership %s: %w", membershipID, err)
	}
	return &m, nil
}

// UpdateMembership sets a role. It is also the create path's final step, so it
// accepts a membership id, a user id, or an email in the request body.
func (c *organizationClientPG) UpdateMembership(ctx context.Context, membershipID string, request *UpdateMembershipRequest) (*OrganizationMembership, error) {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return nil, err
	}

	var id string
	err = c.pool.QueryRow(ctx, `
		UPDATE organization_memberships m
		   SET role = $3::"Role", updated_at = CURRENT_TIMESTAMP
		  FROM users u
		 WHERE u.id = m.user_id
		   AND m.org_id = $1
		   AND (m.id = $2 OR m.user_id = $2 OR ($4 <> '' AND u.email = $4))
		RETURNING m.id`,
		orgID, membershipID, request.Role, request.Email).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrMembershipNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update membership %s: %w", membershipID, err)
	}

	return c.GetMembership(ctx, id)
}

// RemoveMember is called by the resource layer with a USER id, despite the
// interface naming the parameter membershipID. Both are accepted rather than
// relying on which one the caller happened to store.
func (c *organizationClientPG) RemoveMember(ctx context.Context, membershipID string) error {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return err
	}

	_, err = c.pool.Exec(ctx, `
		DELETE FROM organization_memberships
		 WHERE org_id = $1 AND (id = $2 OR user_id = $2)`, orgID, membershipID)
	if err != nil {
		return fmt.Errorf("failed to remove member %s: %w", membershipID, err)
	}
	return nil
}

// CreateSCIMUser provisions a user and places them in the organization.
//
// Two things the HTTP version did implicitly and the resource layer depends on:
// the call also creates the ORGANIZATION MEMBERSHIP (the caller immediately
// re-lists memberships and expects to find one for the returned user id), and it
// tolerates a user who already exists -- SSO will have created a row the first
// time that person logged in, and that is the common case, not an error.
//
// The membership is created with role NONE. The caller sets the real role in the
// very next call; if that fails, the safe residue is a member who can see
// nothing rather than one who was silently granted access.
func (c *organizationClientPG) CreateSCIMUser(ctx context.Context, request *SCIMUserRequest) (*SCIMUserResponse, error) {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return nil, err
	}

	email := request.UserName
	for _, e := range request.Emails {
		if e.Primary && e.Value != "" {
			email = e.Value
			break
		}
	}
	if email == "" {
		return nil, fmt.Errorf("an email address is required to provision a user")
	}

	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	err = tx.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		userID = cuid.New()
		// No password: this account signs in through SSO, exactly as one
		// created by a first login would.
		if _, err := tx.Exec(ctx, `
			INSERT INTO users (id, email, name, created_at, updated_at)
			VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
			userID, email, request.UserName); err != nil {
			return nil, fmt.Errorf("failed to create user %s: %w", email, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to look up user %s: %w", email, err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_memberships (id, org_id, user_id, role, created_at, updated_at)
		VALUES ($1, $2, $3, 'NONE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (org_id, user_id) DO NOTHING`,
		cuid.New(), orgID, userID); err != nil {
		return nil, fmt.Errorf("failed to add %s to organization %s: %w", email, orgID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit user provisioning: %w", err)
	}

	return &SCIMUserResponse{ID: userID, UserName: request.UserName, Active: true}, nil
}

// -- project memberships ------------------------------------------------------

func (c *organizationClientPG) ListProjectMemberships(ctx context.Context, projectID string) ([]ProjectMembership, error) {
	if _, err := c.GetProject(ctx, projectID); err != nil {
		return nil, err
	}

	rows, err := c.pool.Query(ctx, `
		SELECT pm.user_id, pm.role::text, COALESCE(u.email, ''), COALESCE(u.name, '')
		  FROM project_memberships pm
		  JOIN users u ON u.id = pm.user_id
		 WHERE pm.project_id = $1
		 ORDER BY pm.created_at`, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list project memberships: %w", err)
	}
	defer rows.Close()

	var memberships []ProjectMembership
	for rows.Next() {
		var m ProjectMembership
		if err := rows.Scan(&m.UserID, &m.Role, &m.Email, &m.Name); err != nil {
			return nil, fmt.Errorf("failed to read project membership: %w", err)
		}
		memberships = append(memberships, m)
	}
	return memberships, rows.Err()
}

func (c *organizationClientPG) GetProjectMembership(ctx context.Context, projectID, membershipID string) (*ProjectMembership, error) {
	if _, err := c.GetProject(ctx, projectID); err != nil {
		return nil, err
	}

	var m ProjectMembership
	err := c.pool.QueryRow(ctx, `
		SELECT pm.user_id, pm.role::text, COALESCE(u.email, ''), COALESCE(u.name, '')
		  FROM project_memberships pm
		  JOIN users u ON u.id = pm.user_id
		 WHERE pm.project_id = $1 AND pm.user_id = $2`,
		projectID, membershipID).Scan(&m.UserID, &m.Role, &m.Email, &m.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrProjectMembershipNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get project membership %s: %w", membershipID, err)
	}
	return &m, nil
}

// CreateOrUpdateProjectMembership requires the user's ORGANIZATION membership:
// project_memberships.org_membership_id is NOT NULL and foreign-keyed to it, so
// a project role cannot exist for someone who is not in the organization. That
// constraint is Langfuse's, and surfacing it plainly beats a raw FK violation.
func (c *organizationClientPG) CreateOrUpdateProjectMembership(ctx context.Context, projectID string, request *CreateProjectMembershipRequest) (*ProjectMembership, error) {
	orgID, err := c.organizationID(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := c.GetProject(ctx, projectID); err != nil {
		return nil, err
	}

	var orgMembershipID string
	err = c.pool.QueryRow(ctx, `
		SELECT id FROM organization_memberships WHERE org_id = $1 AND user_id = $2`,
		orgID, request.UserID).Scan(&orgMembershipID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("user %s is not a member of organization %s; add a langfuse_organization_membership first", request.UserID, orgID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to resolve organization membership: %w", err)
	}

	if _, err := c.pool.Exec(ctx, `
		INSERT INTO project_memberships (project_id, user_id, org_membership_id, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4::"Role", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (project_id, user_id)
		DO UPDATE SET role = EXCLUDED.role, updated_at = CURRENT_TIMESTAMP`,
		projectID, request.UserID, orgMembershipID, request.Role); err != nil {
		return nil, fmt.Errorf("failed to set project membership: %w", err)
	}

	return c.GetProjectMembership(ctx, projectID, request.UserID)
}

func (c *organizationClientPG) DeleteProjectMembership(ctx context.Context, projectID, userID string) error {
	_, err := c.pool.Exec(ctx, `
		DELETE FROM project_memberships WHERE project_id = $1 AND user_id = $2`,
		projectID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete project membership: %w", err)
	}
	return nil
}
