# Implement Location Based Authorization

## Description

Implement location-based JWT authorization for a specific controller in an ASP.NET Core microservice following RELEX patterns. This command provides step-by-step instructions for setting up location-based authentication policies and comprehensive testing for the specified controller.

**IMPORTANT**: This command should ONLY be used when endpoints actually need location-based authorization added or modified. If the controller already has appropriate authorization (scope-based or location-based), no changes should be made.

## Usage

```bash
/implement-location-based-authorization <ControllerName>
```

**Examples**:
```bash
/implement-location-based-authorization PlanogramFeedbackPermissionsController
/implement-location-based-authorization AuditLogsController
/implement-location-based-authorization PlanogramController
```

## Prerequisites

- ASP.NET Core Web API project
- Access to RELEX NuGet packages
- Understanding of JWT token-based authentication
- Existing controller that needs location-based authorization added (not just any authorization)
- Familiarity with ASP.NET Core authorization policies

## Before Starting

**CRITICAL**: Always analyze the controller first to determine if changes are actually needed:

1. **⚠️ MANDATORY FIRST CHECK - SHARED CONTROLLERS/ENDPOINTS ⚠️**:

   **DO NOT IMPLEMENT LOCATION-BASED AUTHORIZATION WHEN:**
   - **Controller is shared between teams** (has both `[Route(StoreOtgPath)]` and `[Route(PlanogramEditorPath)]` attributes)
   - **OR individual endpoints are shared between teams** (even in non-shared controllers)

   **Examples of what NOT to modify**:
   - HighlightsController → Has both route attributes → **DO NOTHING**
   - PlanogramInteractionController → Has both route attributes → **DO NOTHING**
   - Any endpoint accessible via both route paths → **DO NOTHING**

   **Why this is critical**: Shared resources serve multiple teams. Modifying them breaks functionality for one or both teams.

2. **Check if controller already has appropriate authorization**:
   - If endpoints already have `[Authorize]` attributes with proper scopes → **DO NOTHING**
   - If endpoints already have location-based authorization → **DO NOTHING**

3. **Determine if location-based authorization is needed**:
   - Are the endpoints location-specific (e.g., store-specific data)?
   - Do they need to restrict access by location codes?
   - If NO → **DO NOT ADD LOCATION-BASED AUTHORIZATION**

4. **Only proceed if ALL conditions are met**:
   - Controller is NOT shared between teams AND
   - Individual endpoints are NOT shared between teams AND
   - Endpoints need location-based authorization AND
   - They don't already have it

## Decision Tree

**Key Principle**: Always prefer refactoring to use the default `locationCode` parameter when possible. Only use custom implementations when breaking changes are not acceptable.

```
Start: Need to add location authorization to an endpoint?
│
├─> Is this endpoint ONLY used by OTG services?
│   └─> YES → **Refactor to use `locationCode` parameter** → Use Case 1 (Default)
│
├─> Is this endpoint ONLY used by the frontend?
│   └─> YES → **Refactor to use `locationCode` parameter** → Use Case 1 (Default)
│
├─> Are other teams depending on this endpoint?
│   └─> YES → **NO BREAKING CHANGES ALLOWED**
│       │
│       ├─> Does endpoint use a different parameter name (e.g., `store`)?
│       │   └─> YES → Use Case 2 (Custom Parameter Name)
│       │
│       └─> Does endpoint use a complex parameter (e.g., comma-separated values)?
│           └─> YES → Use Case 3 (Custom Handler)
│
└─> Default: Use Case 1 (Default Handling)
```

## Required NuGet Package

```xml
<PackageReference Include="Relex.Core.Web" Version="3.3.137" />
```

**Note**: The `Relex.Core.Web` package includes all necessary dependencies for location-based authorization.

## Step 1: Register Default Policies in Startup.cs

**IMPORTANT**: The authorization policies are likely already configured in your service. Verify the following configuration exists in your `Startup.cs`:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services
        .AddHttpUserContext()
        .AddAuthorizationPolicies()
        .AddDefaultLocationAuthorizationPolicies() // This line enables default location authorization
        .AddAuthentication(JwtAuthenticationDefaults.AuthenticationScheme)
        .AddJwt(options => options.VerifySignature = false);

    services.AddClaimsIdentityFactory(); // needed for array-based scope

    // Your existing authorization policies
    services
        .AddAuthorizationBuilder()
        .AddPolicy("PlanogramAccess", policy =>
            policy.RequireAssertion(context =>
                context.User.HasClaim("scope", Scope.Planogram.PlanogramView) ||
                context.User.HasClaim("scope", Scope.Planogram.PlanogramEdit)
            ));
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();
    app.UseEndpoints(endpoints => endpoints.MapControllers());
}
```

## Step 2: Modify Controller to Add Authorization

**MANDATORY REQUIREMENT**: Your controller MUST inherit from `AuthorizeControllerBase` and NOTHING ELSE.

### 2.1: Add Required Using Statements

```csharp
using Microsoft.AspNetCore.Authorization;
using Relex.Core.Web.Security.Controllers;
using Relex.Core.Web.Security.Authorization;
```

### 2.2: Modify Controller Base Class - MANDATORY

**BEFORE:**
```csharp
public class YourController : ControllerBase
{
    // Current implementation
}
```

**AFTER:**
```csharp
public class YourController : AuthorizeControllerBase // REQUIRED: Must inherit from AuthorizeControllerBase
{
    // Implementation with access to RequestContext and AuthTokenValue
}
```

## Use Cases

### Use Case 1: Default Handling (Recommended)

**When to use**: Endpoint accepts a single `locationCode` query parameter.

**Implementation**:
```csharp
[HttpGet]
[Route("")]
[Authorize(Policy = "PlanogramAccess")]
[Authorize(Policy = CustomAuthorizationPolicies.AuthorizeLocationsByQuery)] // Add this line
public async Task<IActionResult> GetData(
    [FromQuery] string? locationCode, // Must be named 'locationCode'
    [FromServices] IRepositoryFactory factory
)
{
    // Implementation
}
```

### Use Case 2: Custom Parameter Name

**When to use**: Endpoint uses a different parameter name (e.g., `store` instead of `locationCode`) and cannot be refactored due to external dependencies.

**Implementation**:

1. **Define Custom Policy in Startup.cs**:
```csharp
services.AddAuthorizationBuilder()
    .AddPolicy(
        "AuthorizeLocationsByStoreParameter",
        policy => policy.Requirements.Add(new QueryLocationAuthorizationRequirement("store"))
    );
```

2. **Apply Policy to Controller Endpoint**:
```csharp
[HttpGet]
[Route("")]
[Authorize(Policy = "PlanogramAccess")]
[Authorize(Policy = "AuthorizeLocationsByStoreParameter")] // Add this line
public async Task<IActionResult> GetData(
    [FromQuery] string? store, // Custom parameter name
    [FromServices] IRepositoryFactory factory
)
{
    // Implementation
}
```

### Use Case 3: Custom Handler (Complex Parameters)

**When to use**: Endpoint accepts complex location parameters (e.g., comma-separated values, arrays, or request body location parsing).

**MANDATORY NAMING CONVENTION**:
- **Query Parameter Handlers**: Use descriptive names like `QueryLocationsAuthorizationHandler`
- **Request Body Handlers**: **MUST** use `RequestBodyAuthorizationHandler` and `RequestBodyAuthorizationRequirement` suffixes (e.g., `AuditLogRequestBodyAuthorizationHandler`, `PlanogramListRequestBodyAuthorizationHandler`)

**Implementation**:

1. **Create Custom Authorization Requirement and Handler**:

**Example: Request Body Handler**:
```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Relex.Core.Web.Security.Authorization;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace YourProject.Security.Authorization;

// Define the requirement - Note the "RequestBody" suffix
public class AuditLogRequestBodyAuthorizationRequirement : LocationAuthorizationRequirementBase
{
    public AuditLogRequestBodyAuthorizationRequirement() : base("requestBody") { }
}

// Implement the handler - Note the "RequestBody" suffix
public class AuditLogRequestBodyAuthorizationHandler(IHttpContextAccessor httpContextAccessor)
    : LocationAuthorizationHandlerBase<AuditLogRequestBodyAuthorizationRequirement>(httpContextAccessor)
{
    protected override HashSet<string> GetRequestedLocations(
        HttpContext httpContext,
        AuditLogRequestBodyAuthorizationRequirement requirement
    )
    {
        // Read request body to get location information
        httpContext.Request.EnableBuffering();
        httpContext.Request.Body.Position = 0;

        using var reader = new StreamReader(httpContext.Request.Body, leaveOpen: true);
        var requestBodyTask = reader.ReadToEndAsync();
        requestBodyTask.Wait(); // Since this is called from synchronous method
        var requestBody = requestBodyTask.Result;
        httpContext.Request.Body.Position = 0;

        if (string.IsNullOrWhiteSpace(requestBody))
        {
            return new HashSet<string>(); // Security: Return empty set instead of wildcard
        }

        var auditLogRequest = JsonSerializer.Deserialize<AuditLogRequest>(requestBody, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        if (auditLogRequest?.LocationCode != null)
        {
            return [auditLogRequest.LocationCode];
        }

        return new HashSet<string>(); // Security: Return empty set instead of wildcard
    }
}
```

2. **Register Handler and Policy in Startup.cs**:
```csharp
// Register custom authorization handlers
services.AddSingleton<IAuthorizationHandler, AuditLogRequestBodyAuthorizationHandler>();

services.AddAuthorizationBuilder()
    .AddPolicy("AuthorizeLocationsByAuditLogRequestBody", policy =>
        policy.Requirements.Add(new AuditLogRequestBodyAuthorizationRequirement()));
```

3. **Apply Policy to Controller Endpoint**:
```csharp
[HttpPost]
[Route("")]
[Authorize(Policy = "PlanogramAccess")]
[Authorize(Policy = "AuthorizeLocationsByAuditLogRequestBody")] // Add this line
public async Task<IActionResult> SaveAuditLog(
    [FromBody] AuditLogRequest requestBody,
    [FromServices] IRepositoryFactory factory
)
{
    // Implementation
}
```

## Step 3: Testing the Implementation

### 3.1: Update Existing Authorization Tests

**IMPORTANT**:
- Do not create new test files
- Only add/update tests for the specific endpoints you modified to include location-based authorization
- Do NOT touch existing tests for other endpoints that were not modified
- Update your existing authorization test files to include location-based authorization tests using the proven RELEX pattern

### Implementation Pattern

Follow the exact structure from `AuditLogsControllerAuthorizationTests.cs`:

```csharp
using Xunit;
using System.Net.Http.Headers;
using Relex.PlanogramManager.Api.Integration.Tests.Authorization.Helpers;
using Relex.Core.Security.Claims;
using System.Text.Json;
using System.Net;

namespace Relex.PlanogramManager.Api.Integration.Tests.Authorization.Controllers;

[Trait("Controller", "YourController")]
public class YourControllerAuthorizationTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private const string BaseControllerUrl = "api/your-endpoint";
    private const string YourEndpointUrl = BaseControllerUrl + "/action";

    #region GET Endpoint Tests

    // UserLocationCodesClaims, UserScopes, LocationCodesRequested, ExpectedStatusCodes
    public static TheoryData<string[]?, string[]?, string[], HttpStatusCode[]> PlanogramAccessScopeTestData()
    {
        return new TheoryData<string[]?, string[]?, string[], HttpStatusCode[]>
        {
            // 401 Unauthorized
            { null, null, ["001", "002"], [HttpStatusCode.Unauthorized] },

            // 403 Forbidden
            // No user scopes & no location codes claim
            { [], [], ["001", "002"], [HttpStatusCode.Forbidden] },
            // Has PlanogramAccess scope only
            { [""], [Scope.Planogram.PlanogramEdit], ["001", "002"], [HttpStatusCode.Forbidden] },
            { [""], [Scope.Planogram.PlanogramView], ["001", "002"], [HttpStatusCode.Forbidden] },
            { [""], [Scope.Planogram.PlanogramEdit, Scope.Planogram.PlanogramView], ["001", "002"], [HttpStatusCode.Forbidden] },
            // Has location codes claim only
            { ["*"], [], ["001", "002"], [HttpStatusCode.Forbidden] },
            { ["001", "002"], [], ["001", "002"], [HttpStatusCode.Forbidden] },
            // Has PlanogramAccess scope & location codes but mismatched location codes
            { ["001"], [Scope.Planogram.PlanogramEdit, Scope.Planogram.PlanogramView], ["002", "001"], [HttpStatusCode.Forbidden] },
            { ["001"], [Scope.Planogram.PlanogramEdit, Scope.Planogram.PlanogramView], ["002", "003"], [HttpStatusCode.Forbidden] },

            // Authorized cases
            { ["*"], [Scope.Planogram.PlanogramView], ["001", "002"], AuthorizationTestHelper.AuthorizedStatusCodes },
            { ["*"], [Scope.Planogram.PlanogramEdit], ["001", "002"], AuthorizationTestHelper.AuthorizedStatusCodes },
            { ["001", "002"], [Scope.Planogram.PlanogramView, Scope.Planogram.PlanogramEdit], ["001", "002"], AuthorizationTestHelper.AuthorizedStatusCodes },
        };
    }

    [Theory]
    [MemberData(nameof(PlanogramAccessScopeTestData))]
    public async Task Get_Request(string[]? userLocationCodesClaims, string[]? userScopes, string[] locationCodesRequested, HttpStatusCode[] expectedStatusCodes)
    {
        // Arrange
        var client = factory.CreateClient();
        if (userLocationCodesClaims is not null && userScopes is not null)
        {
            var jwtToken = JwtTokenHelper.CustomJwtToken(string.Join(",", userLocationCodesClaims), userScopes);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
        }

        // Act - Replace with your actual endpoint URL and parameter
        var response = await client.GetAsync(YourEndpointUrl + $"?locationCode={locationCodesRequested[0]}");

        // Assert
        Assert.Contains(response.StatusCode, expectedStatusCodes);
    }

    #endregion

    #region POST Endpoint Tests

    [Theory]
    [MemberData(nameof(PlanogramAccessScopeTestData))]
    public async Task Post_Request(string[]? userLocationCodesClaims, string[]? userScopes, string[] locationCodesRequested, HttpStatusCode[] expectedStatusCodes)
    {
        // Arrange
        var client = factory.CreateClient();
        if (userLocationCodesClaims is not null && userScopes is not null)
        {
            var jwtToken = JwtTokenHelper.CustomJwtToken(string.Join(",", userLocationCodesClaims), userScopes);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
        }

        // Create request body with location from test data - ADAPT TO YOUR MODEL
        var requestModel = new { LocationCode = locationCodesRequested[0], /* Add other required properties */ };
        var requestBody = new StringContent(JsonSerializer.Serialize(requestModel), System.Text.Encoding.UTF8, "application/json");

        // Act
        var response = await client.PostAsync(YourEndpointUrl, requestBody);

        // Assert
        Assert.Contains(response.StatusCode, expectedStatusCodes);
    }

    #endregion
}
```

### 3.2: Critical Testing Guidelines

**IMPORTANT**: Use different test data structures based on endpoint authorization type:

#### Non-Location-Based Endpoints (Scope-Only Authorization)
For existing endpoints that only require scopes and don't need location authorization:

```csharp
#region Non-Location-Based Endpoint Tests

// Data for parameterized tests
// UserScopes, ExpectedStatusCodes
public static TheoryData<string[]?, HttpStatusCode[]> PlanogramSharedAccessScopeTestData()
{
    return new TheoryData<string[]?, HttpStatusCode[]>
    {
        // 401 Unauthorized
        { null, [HttpStatusCode.Unauthorized] },

        // 403 Forbidden
        // No user scopes
        { [], [HttpStatusCode.Forbidden] },
        // Has other scopes (not allowed for PlanogramSharedAccess endpoints)
        { [Scope.Administration.AccountSettingsView], [HttpStatusCode.Forbidden] },

        // Authorized cases - Has required PlanogramSharedAccess scopes
        { [Scope.Planogram.PlanogramView], AuthorizationTestHelper.AuthorizedStatusCodes },
        { [Scope.Planogram.PlanogramEdit], AuthorizationTestHelper.AuthorizedStatusCodes },
        { [Scope.Planogram.PlanogramView, Scope.Planogram.PlanogramEdit], AuthorizationTestHelper.AuthorizedStatusCodes },
    };
}

// Data for parameterized tests
// UserScopes, ExpectedStatusCodes
public static TheoryData<string[]?, HttpStatusCode[]> PlanogramEditScopeTestData()
{
    return new TheoryData<string[]?, HttpStatusCode[]>
    {
        // 401 Unauthorized
        { null, [HttpStatusCode.Unauthorized] },

        // 403 Forbidden
        // No user scopes
        { [], [HttpStatusCode.Forbidden] },
        // Has view scope only (not sufficient for edit operations)
        { [Scope.Planogram.PlanogramView], [HttpStatusCode.Forbidden] },
        // Has other scopes
        { [Scope.Administration.AccountSettingsView], [HttpStatusCode.Forbidden] },

        // Authorized cases - Has required PlanogramEdit scope
        { [Scope.Planogram.PlanogramEdit], AuthorizationTestHelper.AuthorizedStatusCodes },
        { [Scope.Planogram.PlanogramView, Scope.Planogram.PlanogramEdit], AuthorizationTestHelper.AuthorizedStatusCodes },
    };
}

[Theory]
[MemberData(nameof(PlanogramSharedAccessScopeTestData))]
public async Task GetYourEndpoint_Request(string[]? userScopes, HttpStatusCode[] expectedStatusCodes)
{
    // Arrange
    var client = _factory.CreateClient();
    if (userScopes is not null)
    {
        var jwtToken = JwtTokenHelper.CustomJwtToken("", userScopes);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
    }

    // Act
    var response = await client.GetAsync("your-get-endpoint-url");

    // Assert
    Assert.Contains(response.StatusCode, expectedStatusCodes);
}

[Theory]
[MemberData(nameof(PlanogramEditScopeTestData))]
public async Task PostYourEndpoint_Request(string[]? userScopes, HttpStatusCode[] expectedStatusCodes)
{
    // Arrange
    var client = _factory.CreateClient();
    if (userScopes is not null)
    {
        var jwtToken = JwtTokenHelper.CustomJwtToken("", userScopes);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
    }

    // Act
    var response = await client.PostAsync("your-post-endpoint-url", new StringContent("your-request-body", Encoding.UTF8, "application/json"));

    // Assert
    Assert.Contains(response.StatusCode, expectedStatusCodes);
}

#endregion
```

#### Location-Based Endpoints
For endpoints that implement location-based authorization and accept locationCode parameters:

```csharp
#region Location-Based Authorization Tests for withChanges Endpoint

// UserLocationCodesClaims, UserScopes, LocationCodesRequested, ExpectedStatusCodes
public static TheoryData<string[]?, string[]?, string[], HttpStatusCode[]> PlanogramSharedAccessScopeTestData()
{
    return new TheoryData<string[]?, string[]?, string[], HttpStatusCode[]>
    {
        // 401 Unauthorized
        { null, null, ["001", "002"], [HttpStatusCode.Unauthorized] },

        // 403 Forbidden
        // No user scopes & no location codes claim
        { [], [], ["001", "002"], [HttpStatusCode.Forbidden] },
        // Has PlanogramSharedAccess scope only
        { [""], [Scope.Planogram.PlanogramEdit], ["001", "002"], [HttpStatusCode.Forbidden] },
        { [""], [Scope.Planogram.PlanogramView], ["001", "002"], [HttpStatusCode.Forbidden] },
        { [""], [Scope.Planogram.PlanogramEdit, Scope.Planogram.PlanogramView], ["001", "002"], [HttpStatusCode.Forbidden] },
        // Has location codes claim only
        { ["*"], [], ["001", "002"], [HttpStatusCode.Forbidden] },
        { ["001", "002"], [], ["001", "002"], [HttpStatusCode.Forbidden] },
        // Has PlanogramSharedAccess scope & location codes but mismatched location codes
        { ["001"], [Scope.Planogram.PlanogramEdit, Scope.Planogram.PlanogramView], ["002", "001"], [HttpStatusCode.Forbidden] },
        { ["001"], [Scope.Planogram.PlanogramEdit, Scope.Planogram.PlanogramView], ["002", "003"], [HttpStatusCode.Forbidden] },

        // Authorized cases
        { ["*"], [Scope.Planogram.PlanogramView], ["001", "002"], AuthorizationTestHelper.AuthorizedStatusCodes },
        { ["*"], [Scope.Planogram.PlanogramEdit], ["001", "002"], AuthorizationTestHelper.AuthorizedStatusCodes },
        { ["001", "002"], [Scope.Planogram.PlanogramView, Scope.Planogram.PlanogramEdit], ["001", "002"], AuthorizationTestHelper.AuthorizedStatusCodes },
    };
}

[Theory]
[MemberData(nameof(PlanogramSharedAccessScopeTestData))]
public async Task GetYourLocationEndpoint_StoreOtgPath_LocationBasedAuthorization(string[]? userLocationCodesClaims, string[]? userScopes, string[] locationCodesRequested, HttpStatusCode[] expectedStatusCodes)
{
    // Arrange
    var client = _factory.CreateClient();
    if (userLocationCodesClaims is not null && userScopes is not null)
    {
        var jwtToken = JwtTokenHelper.CustomJwtToken(string.Join(",", userLocationCodesClaims), userScopes);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
    }

    var url = $"{StoreOtgPath}/withChanges/123e4567-e89b-12d3-a456-426614174000/123e4567-e89b-12d3-a456-426614174001?locationCode={locationCodesRequested[0]}&categoryCode=TEST";

    // Act
    var response = await client.GetAsync(url);

    // Assert
    Assert.Contains(response.StatusCode, expectedStatusCodes);
}

#endregion
```

### 3.3: Verify JWT Token Helper

Ensure your existing `JwtTokenHelper.cs` includes the `CustomJwtToken` method. This method is essential for location-based authorization testing and should already exist in the helpers.

## Step 4: Critical Rules

**DO NOT**:
- Modify existing test files from other controllers
- Create new test files - update existing controller test file
- Modify `JwtTokenHelper.cs` - use existing `CustomJwtToken` method
- Modify `AuditLogAuthorizationHandlers.cs` - keep original content
- Use location-based test data structure for scope-only endpoints

**DO**:
- Follow exact same structure as `AuditLogsControllerAuthorizationTests.cs`
- Use appropriate test data structure based on endpoint authorization type
- Update only the target controller's test file
- Inherit from `AuthorizeControllerBase` (not `ControllerBase`)

**Files to Never Modify**:
- `JwtTokenHelper.cs` - Use existing `CustomJwtToken(locationCode, scopes)` method
- `AuditLogAuthorizationHandlers.cs` - Keep original content with both handlers
- Other controller test files - Only update the target controller's test file

## Step 5: Common Pitfalls to Avoid

1. **Wrong base class inheritance**: Always use `AuthorizeControllerBase`, never `ControllerBase` or `Controller`
2. **Missing location parameters**: Endpoints requiring location authorization must accept location parameters
3. **Incorrect parameter naming**: Use `locationCode` unless external dependencies prevent it
4. **Missing using statements**: Ensure all required namespaces are imported
5. **Wrong test data structure**: Use scope-only structure for endpoints without location authorization

## Step 5: Validation Checklist

Before completing implementation, verify:

### Code Implementation
- [ ] Controller inherits from `AuthorizeControllerBase` (not `ControllerBase` or `Controller`)
- [ ] All required using statements are added
- [ ] All endpoints have appropriate `[Authorize]` attributes for scope validation
- [ ] Location-based endpoints have location authorization attributes
- [ ] Location parameters use correct names (`locationCode` preferred)

### Testing
- [ ] Updated existing authorization test file (don't create new files)
- [ ] Tests follow the `AuditLogsControllerAuthorizationTests.cs` pattern
- [ ] Test class uses `[Trait("Controller", "YourController")]` attribute
- [ ] Tests use `ApiFactory` and `AuthorizedStatusCodes` for assertions

## Step 6: Common Issues

### Custom Handler Issues
- **Handler not executing**: Ensure handler is registered as `IAuthorizationHandler` in Startup.cs
- **Policy not found**: Verify policy registration and correct naming
- **Request body parsing**: Use `httpContext.Request.EnableBuffering()` and reset stream position

### Test Issues
- **Test data structure**: Ensure anonymous objects match your actual model properties
- **JWT tokens**: Use `JwtTokenHelper.CustomJwtToken(locationCode, [scopes])` for location testing

## Summary

| Use Case | When to Use | Complexity | Requires Custom Code |
|----------|-------------|------------|---------------------|
| Case 1: Default | Parameter named `locationCode` | Low | No |
| Case 2: Custom Parameter | Different parameter name, can't refactor | Medium | Minimal (policy config) |
| Case 3: Custom Handler | Complex parsing (arrays, comma-separated, request body) | High | Yes (handler class) |

**Best Practice**: Always start with the decision tree. Refactor to use Case 1 unless external dependencies prevent it.

## When No Changes Are Needed

If after analyzing the controller you determine that no changes are needed, report this clearly:

### Examples of when to do nothing:

1. **Controller is shared between teams**:
   ```
   Analysis: PlanogramInteractionController has both [Route(StoreOtgPath)] and [Route(PlanogramEditorPath)] attributes.
   This indicates it's shared between teams and should not be modified.
   Result: No changes needed.
   ```

2. **Individual endpoints are shared between teams**:
   ```
   Analysis: While the controller is team-specific, the GetSomething endpoint serves both teams
   through shared routing or accessibility. Modifying this endpoint would break functionality for one team.
   Result: No changes needed for shared endpoints.
   ```

3. **Controller already has appropriate scope-based authorization**:
   ```
   Analysis: FixtureLabelController already has proper authorization:
   - [Authorize(Policy = Scope.Planogram.PlanogramEdit)]
   - [Authorize(Policy = "PlanogramAccess")]
   - Tests already exist and are working correctly
   Result: No changes needed.
   ```

4. **Controller already has location-based authorization**:
   ```
   Analysis: AuditLogsController already has location-based authorization implemented.
   Result: No changes needed.
   ```

4. **Controller doesn't need location-based authorization**:
   ```
   Analysis: Endpoints operate on account-scoped data, not location-specific data.
   Result: Location-based authorization not appropriate for this controller.
   ```

**CRITICAL RULE**: Only modify files when endpoints actually need location-based authorization added or modified.