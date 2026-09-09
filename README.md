markdown# Mundus.Security.Client
> The Ultimate Plug-and-Play Identity & Access Federation Client for .NET Ecosystems.

[![NuGet Version](https://shields.io)](https://nuget.org)
[![License: MIT](https://shields.io)](https://opensource.org)

**Mundus.Security.Client** is an enterprise-grade, high-performance, and resilient federated identity client library designed to seamlessly connect any .NET application (Satelite API) to the **Mundus Security CIAM** platform. 

Built under strict Domain-Driven Design (DDD) guidelines and Uncle Bob's Clean Code principles, this package abstracts all the complexity of Multi-Tenant, Multi-App token validation, high-speed RAM caching, and Server-to-Server (M2M) communications, delivering an unmatched Developer Experience (DevEx).

---

## 💎 Core Architecture & Features

* **Zero-Knowledge Token Validation:** Mathematical validation of HMAC SHA-256 JWT tokens is performed entirely in the Satellite's RAM memory, requiring zero contact or direct connection with the Mundus Security central database during active sessions.
* **Smart Dynamic RAM Caching:** Implements native `IMemoryCache` that automatically syncs encryption keys and authorized audience domains according to the expiration parameters defined in the enterprise tenant's contract.
* **Native Resilience Engine (Polly V8):** Armed with an enterprise-grade standard resilience handler featuring Exponential Backoff with Jitter (3 retry attempts) and automatic Circuit Breaking to gracefully handle micro-instabilities in cloud networks.
* **Thread-Safe Multi-Tenant Isolation:** Complete protection against race conditions and cross-user data leakage. All dynamic HTTP headers (such as user-specific bearer tokens and contextual client metadata) are processed using isolated request messages per execution thread.
* **Agnostic & Imutable Integration:** Fully decoupled from central endpoint paths. Future architectural expansions in the central CIAM will never force your clients to upgrade this package.

---

## 🛠️ Step-by-Step Infrastructure Setup

Mundus.Security.Client extracts your corporate secrets directly from the runtime process isolation. Configure the following 5 mandatory environment variables in your deployment pipeline or host environment:

### 1. Microsoft IIS (web.config)
```xml
<environmentVariables>
  <environmentVariable name="MUNDUS_COMPANY_CODE" value="YOUR_COMPANY_CODE" />
  <environmentVariable name="MUNDUS_APPLICATION_CODE" value="YOUR_APPLICATION_CODE" />
  <environmentVariable name="MUNDUS_CLIENT_ID" value="YOUR_M2M_CLIENT_ID" />
  <environmentVariable name="MUNDUS_CLIENT_SECRET" value="YOUR_M2M_CLIENT_SECRET" />
  <environmentVariable name="MUNDUS_SECURITY_URL" value="https://mundussecurity.com" />
</environmentVariables>
```

### 2. Docker & Docker Compose (`docker-compose.yml`)
```yaml
environment:
  - MUNDUS_COMPANY_CODE=YOUR_COMPANY_CODE
  - MUNDUS_APPLICATION_CODE=YOUR_APPLICATION_CODE
  - MUNDUS_CLIENT_ID=YOUR_M2M_CLIENT_ID
  - MUNDUS_CLIENT_SECRET=YOUR_M2M_CLIENT_SECRET
  - MUNDUS_SECURITY_URL=https://mundussecurity.com
```

### 3. Linux Ubuntu / Debian Systemd Service (`.service`)
```ini
Environment=MUNDUS_COMPANY_CODE=YOUR_COMPANY_CODE
Environment=MUNDUS_APPLICATION_CODE=YOUR_APPLICATION_CODE
Environment=MUNDUS_CLIENT_ID=YOUR_M2M_CLIENT_ID
Environment=MUNDUS_CLIENT_SECRET=YOUR_M2M_CLIENT_SECRET
Environment=MUNDUS_SECURITY_URL=https://mundussecurity.com
```

### 4. Cloud Serverless Options (AWS Lambda / Azure Functions / GCP Run)
* **AWS Lambda:** Access *Configuration* -> *Environment variables* -> Add keys.
* **Azure Functions:** Access *Settings* -> *Environment variables* -> Add keys.
* **Google Cloud Run:** Access *Edit & Deploy New Revision* -> *Variables & Secrets* -> Add keys.

---

## 🚀 Quick Start & Integration Code

### 1. Package Registration (`Program.cs`)
Initialize the middleware pipeline with a single line of code. This extension reads environment variables, registers the resilient `HttpClient` factory, and configures the dynamic JWT bearer authentication handler:

```csharp
var builder = WebApplication.CreateBuilder(args);

// 👇 The magic line that bootstraps the entire federation framework
builder.Services.AddMundusAuthentication();

builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication(); // 1st: Validates token signatures in local RAM
app.UseAuthorization();  // 2nd: Checks hierarchical access control and roles

app.MapControllers();
app.Run();
```

### 2. Traditional MVC Controller Implementation
Your developers maintain complete control over routing and business logic by creating traditional controllers. Inject the lightweight `MundusHttpClient` service to safely talk to the CIAM without exposing core environmental secrets:

```csharp
[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly MundusHttpClient _mundusHttp;

    public AccountController(MundusHttpClient mundusHttp)
    {
        _mundusHttp = mundusHttp;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDTO loginDto)
    {
        // Context code automatically populated by the package
        loginDto.ApplicationCode = _mundusHttp.ApplicationCode;

        // Clean, structured, and branded server-to-server dispatch
        var response = await _mundusHttp.PostToMundusSecurityAsync("account/login", loginDto);
        
        if (!response.IsSuccessStatusCode)
            return StatusCode((int)response.StatusCode, await response.Content.ReadAsStringAsync());

        return Ok(await response.Content.ReadAsStringAsync());
    }
}
```

```csharp
[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly MundusHttpClient _mundusHttp;

    public UserController(MundusHttpClient mundusHttp)
    {
        _mundusHttp = mundusHttp;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDTO registerDto)
    {
        // Seamlessly inject secure application and company scope codes
        registerDto.ApplicationCode = _mundusHttp.ApplicationCode;
        registerDto.CompanyCode = _mundusHttp.CompanyCode;

        // 🌟 Explicit Machine-to-Machine (M2M) backend request signing
        var response = await _mundusHttp.PostToMundusSecurityAsMachineAsync("account/register", registerDto);

        if (!response.IsSuccessStatusCode)
            return StatusCode((int)response.StatusCode, await response.Content.ReadAsStringAsync());

        return Ok(await response.Content.ReadAsStringAsync());
    }
}
```

---

## 📊 Live API Reference Matrix

Developers can consult our live interactive sandbox reference interface at `https://mundussecurity.com` or use this quick mapping matrix:

| Business Intent | CIAM Central Path | HTTP Verb | Recommended Client Method |
| :--- | :--- | :--- | :--- |
| **Authenticate Human User** | `account/login` | `POST` | `PostToMundusSecurityAsync(path, payload)` |
| **Register Root Account/User** | `account/register` | `POST` | `PostToMundusSecurityAsMachineAsync(path, payload)` |
| **Query Application Data** | `application/by-code/{code}` | `GET` | `GetFromMundusSecurityAsync(path)` |
| **Update Tenant Configurations** | `tenant/update` | `PUT` | `PutToMundusSecurityAsync(path, payload)` |
| **Purge User Records (Support)** | `account/delete/{id}` | `DELETE` | `DeleteFromMundusSecurityAsync(path)` |

---

## 🛡️ Governance & Enterprise Resiliency Logging

All critical connection and infrastructure anomalies are internally captured under the **fail-closed** paradigm. When network transport collapses, Mundus.Security.Client automatically populates your native logging target (Console, Serilog, Datadog, or Azure AppInsights) with the standardized tracking tag:

`[MUNDUS_SECURITY_ERROR] Mundus Security platform is inaccessible.`

This isolation layer ensures that local cluster logging administrators can instantly isolate external connection problems, minimizing your team's ungrounded support maintenance tickets.

---

## ⚖️ License
Distributed under the MIT License. See `LICENSE` for more information.
