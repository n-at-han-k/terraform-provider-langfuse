package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/langfuse/terraform-provider-langfuse/internal/langfuse"
)

var _ provider.Provider = &langfuseProvider{}

type langfuseProvider struct {
	version string
}

type langfuseProviderModel struct {
	Database      types.String `tfsdk:"database"`
	Salt          types.String `tfsdk:"salt"`
	EncryptionKey types.String `tfsdk:"encryption_key"`
}

func (p *langfuseProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "langfuse"
	resp.Version = p.version
}

func (p *langfuseProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages Langfuse organizations, projects, API keys and memberships by writing " +
			"directly to the Langfuse Postgres database.\n\n" +
			"Upstream this provider drives Langfuse's Instance Management API, which is only available in the " +
			"Enterprise Edition. This fork talks to the database instead, so it works on the self-hosted OSS " +
			"edition with no licence key.",
		Attributes: map[string]schema.Attribute{
			"database": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "Connection string for the Langfuse Postgres database, in libpq keyword/value or URL form " +
					"(e.g. \"host=... dbname=langfuse user=... password=...\"). Can also come from LANGFUSE_DATABASE_URL.",
			},
			"salt": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "The Langfuse instance's SALT, the same value passed to langfuse-web as the SALT " +
					"environment variable. API key hashes are derived from it, so a wrong value mints keys the " +
					"database accepts and Langfuse then rejects on every request. Can also come from LANGFUSE_SALT " +
					"or SALT.",
			},
			"encryption_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "The Langfuse instance's ENCRYPTION_KEY. Reserved for LLM connection support, which is " +
					"not yet implemented against the database. Can also come from LANGFUSE_ENCRYPTION_KEY.",
			},
		},
	}
}

func (p *langfuseProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config langfuseProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if config.Database.IsUnknown() || config.Salt.IsUnknown() || config.EncryptionKey.IsUnknown() {
		return
	}

	// Configuration wins over the environment, so a workspace can be explicit
	// without having to clear inherited variables.
	database := firstNonEmpty(config.Database.ValueString(), os.Getenv("LANGFUSE_DATABASE_URL"))

	// SALT is read under its Langfuse-side name too. The value is delivered to
	// langfuse-web as SALT, and requiring it to be renamed on the way into the
	// provider is one more place for the two to drift apart.
	salt := firstNonEmpty(config.Salt.ValueString(), os.Getenv("LANGFUSE_SALT"), os.Getenv("SALT"))

	encryptionKey := firstNonEmpty(config.EncryptionKey.ValueString(), os.Getenv("LANGFUSE_ENCRYPTION_KEY"), os.Getenv("ENCRYPTION_KEY"))

	if database == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("database"),
			"Missing Langfuse database connection string",
			"Set the provider's `database` argument or the LANGFUSE_DATABASE_URL environment variable.",
		)
		return
	}

	// Not fatal: reads and organization/membership writes work without it, and
	// failing configuration outright would block them too. Minting an API key
	// without it fails loudly at that point instead.
	if salt == "" {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("salt"),
			"No Langfuse SALT configured",
			"Creating API keys requires the instance's SALT to derive the hashes Langfuse checks at "+
				"authentication time. Set the `salt` argument or the LANGFUSE_SALT environment variable.",
		)
	}

	clientFactory, err := langfuse.NewClientFactory(ctx, database, salt, encryptionKey)
	if err != nil {
		resp.Diagnostics.AddError("Unable to connect to the Langfuse database", err.Error())
		return
	}

	resp.DataSourceData = clientFactory
	resp.ResourceData = clientFactory
}

func (p *langfuseProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *langfuseProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewOrganizationResource,
		NewOrganizationApiKeyResource,
		NewOrganizationMembershipResource,
		NewProjectResource,
		NewProjectApiKeyResource,
		NewProjectMembershipResource,
		NewLlmConnectionResource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &langfuseProvider{version: version}
	}
}

// firstNonEmpty returns the first non-empty value, used to layer explicit
// configuration over environment fallbacks.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
