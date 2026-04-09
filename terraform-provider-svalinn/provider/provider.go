// SPDX-License-Identifier: PMPL-1.0-or-later
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// Provider configuration
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_url": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("SVALINN_API_URL", "http://localhost:8443"),
				Description: "Svalinn Vault API URL",
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("SVALINN_API_KEY", nil),
				Description: "Svalinn Vault API Key",
			},
			"insecure": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Allow insecure connections (for testing only)",
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"svalinn_user":                resourceSvalinnUser(),
			"svalinn_credential":          resourceSvalinnCredential(),
			"svalinn_mfa_policy":         resourceSvalinnMFAPolicy(),
			"svalinn_backup_config":      resourceSvalinnBackupConfig(),
			"svalinn_compliance_profile": resourceSvalinnComplianceProfile(),
		},

		DataSourcesMap: map[string]*schema.Resource{
			"svalinn_user":           dataSourceSvalinnUser(),
			"svalinn_credentials":    dataSourceSvalinnCredentials(),
			"svalinn_mfa_status":     dataSourceSvalinnMFAStatus(),
			"svalinn_backup_status":  dataSourceSvalinnBackupStatus(),
		},

		ConfigureContextFunc: providerConfigure,
	}
}

// Provider configuration
func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	apiUrl := d.Get("api_url").(string)
	apiKey := d.Get("api_key").(string)
	insecure := d.Get("insecure").(bool)

	// Create client
	client, err := NewClient(apiUrl, apiKey, insecure)
	if err != nil {
		return nil, diag.FromErr(err)
	}

	return client, diags
}

// Client for Svalinn API
type Client struct {
	ApiUrl    string
	ApiKey    string
	Insecure  bool
	HttpClient *http.Client
}

func NewClient(apiUrl, apiKey string, insecure bool) (*Client, error) {
	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	if insecure {
		// Disable TLS verification for testing
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}

	return &Client{
		ApiUrl:    apiUrl,
		ApiKey:    apiKey,
		Insecure:  insecure,
		HttpClient: httpClient,
	}, nil
}

// User resource
func resourceSvalinnUser() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSvalinnUserCreate,
		ReadContext:   resourceSvalinnUserRead,
		UpdateContext: resourceSvalinnUserUpdate,
		DeleteContext: resourceSvalinnUserDelete,

		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "User username/email",
			},
			"display_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User display name",
			},
			"mfa_required": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Require MFA for this user",
			},
			"compliance_profile": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "nist_aal2",
				Description: "Compliance profile (nist_aal2, iso_27001, soc_2, hipaa, gdpr)",
				ValidateFunc: validation.StringInSlice([]string{
					"nist_aal2", "iso_27001", "soc_2", "hipaa", "gdpr",
				}, false),
			},
			"status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "User status (active, locked, disabled)",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "User creation timestamp",
			},
			"last_login": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last login timestamp",
			},
		},
	}
}

func resourceSvalinnUserCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)
	
	// Get attributes
	username := d.Get("username").(string)
	displayName := d.Get("display_name").(string)
	mfaRequired := d.Get("mfa_required").(bool)
	complianceProfile := d.Get("compliance_profile").(string)
	
	// Create user via API
	userId, err := client.CreateUser(username, displayName, mfaRequired, complianceProfile)
	if err != nil {
		return diag.FromErr(err)
	}
	
	d.SetId(userId)
	return resourceSvalinnUserRead(ctx, d, m)
}

func resourceSvalinnUserRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)
	
	// Get user via API
	user, err := client.GetUser(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	
	// Set attributes
	d.Set("username", user.Username)
	d.Set("display_name", user.DisplayName)
	d.Set("mfa_required", user.MFARequired)
	d.Set("compliance_profile", user.ComplianceProfile)
	d.Set("status", user.Status)
	d.Set("created_at", user.CreatedAt)
	d.Set("last_login", user.LastLogin)
	
	return nil
}

// Update, Delete, and other resources would follow similar patterns
