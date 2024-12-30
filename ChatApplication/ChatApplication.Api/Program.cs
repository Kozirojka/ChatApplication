using System.Net.Http.Headers;
using System.Security.Claims;
using ChatApplication.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<ApplicationDbContext>(options => 
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));


builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();


builder.Services.AddDistributedMemoryCache(); 
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie", o =>
    {
        o.LoginPath = "/login";
        var del = o.Events.OnRedirectToAccessDenied;
        o.Events.OnRedirectToAccessDenied = context =>
        {
            if (context.Request.Path.StartsWithSegments("/yt"))
            {
                return context.HttpContext.ChallengeAsync("youtube");
            }
            return del(context);
        };
    }).AddOAuth("youtube", o =>
    {
        o.SignInScheme = "cookie";

        o.ClientId = builder.Configuration.GetSection("Youtube:ClientId").Value;
 
        o.ClientSecret = builder.Configuration.GetSection("Youtube:ClientSecret").Value;

        o.SaveTokens = false;

        o.Scope.Clear();

        o.Scope.Add("https://www.googleapis.com/auth/youtube.readonly");
        o.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";


        o.TokenEndpoint = "https://oauth2.googleapis.com/token";

        o.CallbackPath = "/oauth/yt-cb";


        o.Events.OnCreatingTicket = async context =>
        {
            var db = context.HttpContext.RequestServices.GetRequiredService<Database>();

            var authenticationHandlerProvider =
                context.HttpContext.RequestServices.GetService<IAuthenticationHandlerProvider>();
            var handler = await authenticationHandlerProvider
                .GetHandlerAsync(context.HttpContext, "cookie");

            var authResult = await handler.AuthenticateAsync();
            if (!authResult.Succeeded)
            {
                context.Fail("failed authentication");
                return;
            }

            var cp = authResult.Principal;



            var userId = cp.FindFirstValue("user_id");
            db[userId] = context.AccessToken;

            context.Principal = cp.Clone();
            var identity = context.Principal.Identities.First(x => x.AuthenticationType == "cookie");

            identity.AddClaim(new Claim("yt-token", "y"));
        };
    }).AddOAuth("google", o =>
    {
        o.SignInScheme = "cookie";
        o.ClientId = builder.Configuration.GetSection("Google:ClientId").Value;
        o.ClientSecret = builder.Configuration.GetSection("Google:ClientSecret").Value;
        
        o.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        
        o.TokenEndpoint = "https://oauth2.googleapis.com/token";

        o.Scope.Add("openid");
        o.Scope.Add("profile");
        o.Scope.Add("email");

        o.CallbackPath = "/oauth/google-cb";

        o.Events.OnCreatingTicket = async context =>
        {
            var returnedState = context.Request.Query["state"].ToString();
            var expectedState = context.HttpContext.Session.GetString("OAuthState");

            if (returnedState != expectedState)
            {
                throw new InvalidOperationException("Invalid OAuth state. Possible CSRF attack.");
            }

            var userInfoEndpoint = "https://www.googleapis.com/oauth2/v3/userinfo";
            var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
            var response = await context.Backchannel.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException("Problem with backchannel response");
            }

            var json = await response.Content.ReadAsStringAsync();
            var user = System.Text.Json.JsonDocument.Parse(json).RootElement;
    
            var identity = (ClaimsIdentity)context.Principal.Identity;
            identity.AddClaim(new Claim(ClaimTypes.Name, user.GetProperty("name").GetString()));
            identity.AddClaim(new Claim(ClaimTypes.Email, user.GetProperty("email").GetString()));
            identity.AddClaim(new Claim("picture", user.GetProperty("picture").GetString()));
        };

    });
    

builder.Services.AddAuthorization(b =>
{
    b.AddPolicy("youtube-enabled",  pb => 
        pb.AddAuthenticationSchemes("cookie")
            .RequireClaim("yt-token", "y")
            .RequireAuthenticatedUser());
});

builder.Services.AddSingleton<Database>().AddTransient<IClaimsTransformation, TokenTransormation>();

builder.Services.AddHttpClient();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {                           
        policy.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader();
    });
});

builder.Services.AddControllers();

var app = builder.Build();





if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseCors("AllowAll");
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();



app.MapGet("/login", () => Results.SignIn(
    new ClaimsPrincipal(
        new ClaimsIdentity(
            new[]
            {
                new Claim("user_id", Guid.NewGuid().ToString())
            },
            "cookie"
            
        )),
    authenticationScheme: "cookie"
));

app.MapGet("/login/google", () =>
{
    var props = new AuthenticationProperties
    {
        RedirectUri = "/profile"
    };
    return Results.Challenge(props, new[] { "google" });
});

app.MapGet("/yt/info", async (IHttpClientFactory clientFactory, HttpContext ctx) =>
{
    
    var accessToken = ctx.User.FindFirstValue("yt-access_token");
    var client = clientFactory.CreateClient();
     
    using var req = new HttpRequestMessage(HttpMethod.Get,
    "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true");
    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    using var response = await client.SendAsync(req);
    return await response.Content.ReadAsStringAsync();
    
}).RequireAuthorization("youtube-enabled");

app.MapGet("/profile", (HttpContext context) =>
{
    if (!context.User.Identity.IsAuthenticated)
    {
        return Results.Unauthorized();
    }

    var name = context.User.FindFirst(ClaimTypes.Name)?.Value;
    var email = context.User.FindFirst(ClaimTypes.Email)?.Value;
    var picture = context.User.FindFirst("picture")?.Value;

    return Results.Json(new
    {
        Name = name,
        Email = email,
        Picture = picture
    });
});

app.Run();


public class Database : Dictionary<string, string>
{
    
}

public class TokenTransormation : IClaimsTransformation
{
    private readonly Database _database;

    public TokenTransormation(Database database)
    {
        _database = database;
    }


    public  Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var userId = principal.FindFirstValue("user_id");

        if (!_database.ContainsKey(userId))
        {
            return Task.FromResult(principal);
        }
        
        var cp = principal.Clone();
        var accessToken = _database[userId];
        
        var identity = cp.Identities.First(x => x.AuthenticationType == "cookie");
        
        identity.AddClaim(new Claim("yt-access_token", accessToken));
        
        return Task.FromResult(cp);
    }
}