package langfuse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lucsky/cuid"
)

// ErrOrganizationNotFound lets callers distinguish "no such row" from a real
// database failure. The resource layer removes a resource from state on the
// former and surfaces a diagnostic on the latter; collapsing the two would make
// a transient outage look like a deletion and quietly drop resources.
var ErrOrganizationNotFound = errors.New("organization not found")

// adminClientPG implements AdminClient against Langfuse's Postgres database
// instead of its Enterprise-only admin API. The interface is unchanged, so
// every resource in internal/provider works untouched.
type adminClientPG struct {
	pool *pgxpool.Pool
	salt string
}

// NewAdminClientPG returns an AdminClient backed by the Langfuse database.
func NewAdminClientPG(pool *pgxpool.Pool, salt string) AdminClient {
	return &adminClientPG{pool: pool, salt: salt}
}

// scanOrganization reads the three columns the AdminClient contract exposes.
// `metadata` is nullable jsonb; a NULL becomes a nil map rather than an error,
// which is what the resource layer expects for "no metadata set".
func scanOrganization(row pgx.Row) (*Organization, error) {
	var (
		org      Organization
		metadata []byte
	)
	if err := row.Scan(&org.ID, &org.Name, &metadata); err != nil {
		return nil, err
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &org.Metadata); err != nil {
			return nil, fmt.Errorf("failed to decode organization metadata: %w", err)
		}
	}
	return &org, nil
}

func (c *adminClientPG) ListOrganizations(ctx context.Context) ([]*Organization, error) {
	rows, err := c.pool.Query(ctx, `SELECT id, name, metadata FROM organizations ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*Organization
	for rows.Next() {
		org, err := scanOrganization(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to read organization: %w", err)
		}
		orgs = append(orgs, org)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}

	return orgs, nil
}

func (c *adminClientPG) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	org, err := scanOrganization(c.pool.QueryRow(ctx,
		`SELECT id, name, metadata FROM organizations WHERE id = $1`, orgID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrOrganizationNotFound, orgID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get organization %s: %w", orgID, err)
	}
	return org, nil
}

func (c *adminClientPG) CreateOrganization(ctx context.Context, request *CreateOrganizationRequest) (*Organization, error) {
	metadata, err := marshalMetadata(request.Metadata)
	if err != nil {
		return nil, err
	}

	// cuid, because that is what Prisma generates for every other row in this
	// database. Nothing constrains the column's format -- Langfuse's own
	// LANGFUSE_INIT_ORG_ID seeding writes a plain human-chosen string -- but
	// matching the convention keeps generated ids indistinguishable from the
	// ones the application makes.
	id := cuid.New()

	org, err := scanOrganization(c.pool.QueryRow(ctx, `
		INSERT INTO organizations (id, name, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		RETURNING id, name, metadata`,
		id, request.Name, metadata))
	if err != nil {
		return nil, fmt.Errorf("failed to create organization %q: %w", request.Name, err)
	}

	return org, nil
}

func (c *adminClientPG) UpdateOrganization(ctx context.Context, orgID string, request *UpdateOrganizationRequest) (*Organization, error) {
	metadata, err := marshalMetadata(request.Metadata)
	if err != nil {
		return nil, err
	}

	org, err := scanOrganization(c.pool.QueryRow(ctx, `
		UPDATE organizations
		   SET name = $2, metadata = $3, updated_at = CURRENT_TIMESTAMP
		 WHERE id = $1
		RETURNING id, name, metadata`,
		orgID, request.Name, metadata))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrOrganizationNotFound, orgID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update organization %s: %w", orgID, err)
	}

	return org, nil
}

// DeleteOrganization removes the organization row. Every dependent row --
// projects, API keys, memberships, invitations -- is declared ON DELETE CASCADE
// in Langfuse's schema, so the database removes them for us. That is a large
// blast radius from one statement, which is why the resource is marked as
// requiring replacement rather than being updated in place where it matters.
func (c *adminClientPG) DeleteOrganization(ctx context.Context, orgID string) error {
	tag, err := c.pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete organization %s: %w", orgID, err)
	}
	// Already gone is a success: Terraform is asking for the row to not exist.
	if tag.RowsAffected() == 0 {
		return nil
	}
	return nil
}

// GetOrganizationApiKey is an existence check. The secret is never recoverable
// -- only its bcrypt and SHA-256 digests are stored -- so the resource layer
// keeps the plaintext it got at creation time in state and uses this only to
// decide whether the row still exists.
func (c *adminClientPG) GetOrganizationApiKey(ctx context.Context, orgID string, apiKeyID string) (*OrganizationApiKey, error) {
	var key OrganizationApiKey
	err := c.pool.QueryRow(ctx, `
		SELECT id, public_key
		  FROM api_keys
		 WHERE id = $1 AND organization_id = $2 AND scope = 'ORGANIZATION'`,
		apiKeyID, orgID).Scan(&key.ID, &key.PublicKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("cannot find API key with ID %s in organization %s", apiKeyID, orgID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API key %s: %w", apiKeyID, err)
	}

	return &key, nil
}

func (c *adminClientPG) CreateOrganizationApiKey(ctx context.Context, orgID string) (*OrganizationApiKey, error) {
	material, err := newAPIKeyMaterial(c.salt)
	if err != nil {
		return nil, err
	}

	id := cuid.New()

	// scope = 'ORGANIZATION' with project_id left NULL is what makes this an
	// org-scoped key; the same table holds project keys with the inverse shape.
	_, err = c.pool.Exec(ctx, `
		INSERT INTO api_keys (
			id, created_at, public_key, hashed_secret_key,
			display_secret_key, fast_hashed_secret_key,
			organization_id, project_id, scope
		) VALUES ($1, CURRENT_TIMESTAMP, $2, $3, $4, $5, $6, NULL, 'ORGANIZATION')`,
		id, material.PublicKey, material.HashedSecretKey,
		material.DisplaySecretKey, material.FastHashedSecretKey, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key for organization %s: %w", orgID, err)
	}

	// The only time the plaintext secret exists. It goes to Terraform state and
	// is never readable again from the database.
	return &OrganizationApiKey{
		ID:        id,
		PublicKey: material.PublicKey,
		SecretKey: material.SecretKey,
	}, nil
}

func (c *adminClientPG) DeleteOrganizationApiKey(ctx context.Context, orgID string, apiKeyID string) error {
	_, err := c.pool.Exec(ctx, `
		DELETE FROM api_keys
		 WHERE id = $1 AND organization_id = $2 AND scope = 'ORGANIZATION'`,
		apiKeyID, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete API key %s in organization %s: %w", apiKeyID, orgID, err)
	}
	return nil
}

// marshalMetadata renders the map the resource layer carries into the jsonb
// column. An empty or absent map becomes SQL NULL rather than `{}` -- Langfuse
// writes NULL for organizations that have never had metadata, and matching that
// keeps an imported organization from showing a spurious diff.
func marshalMetadata(metadata map[string]string) (any, error) {
	if len(metadata) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to encode metadata: %w", err)
	}
	return encoded, nil
}
