package langfuse

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Langfuse's Instance Management API -- the only way to create organizations
// and organization-scoped API keys over HTTP -- is gated behind an Enterprise
// licence. This provider talks to the Postgres database Langfuse itself writes,
// which is not gated, and is the same approach glauth-passbolt takes to the
// passbolt directory.
//
// The trade is explicit: no licence needed, but nothing validates the writes on
// the way in. Every statement here has to satisfy the constraints Langfuse's
// Prisma schema declares, and the derived columns in keys_pg.go have to match
// what Langfuse computes at read time. Where a value is a Langfuse convention
// rather than a database constraint, it is called out at the site.

// newPool opens a lazily-connecting pool against the Langfuse database.
//
// pgx does not dial here, so a bad host does not fail provider configuration --
// it fails on the first resource operation, with the statement that needed it.
// That is the behaviour we want from Terraform: `plan` on unrelated resources
// should not require the database to be reachable.
func newPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	if dsn == "" {
		return nil, fmt.Errorf("the provider's `database` argument is required: it is the connection string for the Langfuse Postgres database")
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the `database` connection string: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create the Langfuse database pool: %w", err)
	}

	return pool, nil
}
