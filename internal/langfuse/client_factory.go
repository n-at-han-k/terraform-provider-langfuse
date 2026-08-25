package langfuse

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type clientFactoryImpl struct {
	pool          *pgxpool.Pool
	salt          string
	encryptionKey string
}

type ClientFactory interface {
	NewAdminClient() AdminClient
	NewOrganizationClient(publicKey, privateKey string) OrganizationClient
	NewLlmConnectionsClient(publicKey, privateKey string) LlmConnectionsClient
}

// NewClientFactory builds clients that talk to Langfuse's Postgres database.
//
// This is the ONE seam that was changed to convert the provider off the
// Enterprise-only admin API. Everything in internal/provider is untouched: the
// AdminClient / OrganizationClient / LlmConnectionsClient interfaces are the
// same, only their implementations moved from HTTP to SQL.
//
// `salt` must be the Langfuse instance's SALT. It is not optional in practice
// -- API key hashes are derived from it, and a wrong value mints keys that the
// database accepts and Langfuse then rejects on every request.
func NewClientFactory(ctx context.Context, dsn, salt, encryptionKey string) (ClientFactory, error) {
	pool, err := newPool(ctx, dsn)
	if err != nil {
		return nil, err
	}

	return &clientFactoryImpl{
		pool:          pool,
		salt:          salt,
		encryptionKey: encryptionKey,
	}, nil
}

func (cf *clientFactoryImpl) NewAdminClient() AdminClient {
	return NewAdminClientPG(cf.pool, cf.salt)
}

// NewOrganizationClient resolves the organization from the API key pair rather
// than authenticating with it.
//
// Over HTTP these two values were Basic-auth credentials, which is what scoped
// every call to one organization. Against the database there is nothing to
// authenticate to, so the public key is used as a LOOKUP instead: it selects
// the api_keys row, which names the organization. The HCL surface is therefore
// unchanged -- `organization_public_key` / `organization_private_key` still
// identify which organization a membership or project belongs to.
func (cf *clientFactoryImpl) NewOrganizationClient(publicKey, privateKey string) OrganizationClient {
	return NewOrganizationClientPG(cf.pool, cf.salt, publicKey, privateKey)
}

func (cf *clientFactoryImpl) NewLlmConnectionsClient(publicKey, privateKey string) LlmConnectionsClient {
	return &llmConnectionsClientUnsupported{}
}

// llmConnectionsClientUnsupported fails loudly rather than silently.
//
// langfuse_llm_connection stores provider credentials encrypted with the
// instance's ENCRYPTION_KEY. Reproducing that cipher against the database is a
// separate piece of reverse engineering from the key hashing in keys_pg.go, and
// getting it subtly wrong would write credentials Langfuse cannot decrypt. Until
// it is implemented and verified against a live instance, the resource refuses
// to run instead of guessing.
type llmConnectionsClientUnsupported struct{}

var errLlmConnectionsUnsupported = fmt.Errorf(
	"langfuse_llm_connection is not supported by the Postgres backend: stored LLM credentials are encrypted with the instance's ENCRYPTION_KEY and that cipher is not yet implemented here; manage LLM connections in the Langfuse UI")

func (c *llmConnectionsClientUnsupported) ListLlmConnections(ctx context.Context, page, limit *int) (*ListLlmConnectionsResponse, error) {
	return nil, errLlmConnectionsUnsupported
}

func (c *llmConnectionsClientUnsupported) UpsertLlmConnection(ctx context.Context, req *UpsertLlmConnectionRequest) (*LlmConnection, error) {
	return nil, errLlmConnectionsUnsupported
}

func (c *llmConnectionsClientUnsupported) DeleteLlmConnection(ctx context.Context, id string) error {
	return errLlmConnectionsUnsupported
}
