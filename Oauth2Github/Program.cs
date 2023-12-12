using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication()
    .AddCookie("external-github", options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
    } )
    .AddOAuth("github", o =>
    {
        o.SignInScheme = "external-github";
        o.ClientId = "";
        o.ClientSecret = "";

        o.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        o.TokenEndpoint = "https://github.com/login/oauth/access_token";
        
        o.UserInformationEndpoint = "https://api.github.com/user";
        o.CallbackPath = "/oauth/github-cb";
        o.SaveTokens = true;
        
        o.ClaimActions.MapJsonKey("sub", "id");
        o.ClaimActions.MapJsonKey(ClaimTypes.Name, "login");
        
        o.Events.OnCreatingTicket = async ctx =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
            using var result = await ctx.Backchannel.SendAsync(request);
            var user = await result.Content.ReadFromJsonAsync<JsonElement>();
            
            ctx.RunClaimActions(user);
        };
    });
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("authenticate" , pb =>
    {
        pb.AddAuthenticationSchemes("external-github")
            .RequireAuthenticatedUser();
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/",async (HttpContext context) =>
{
    Console.WriteLine(await context.GetTokenAsync("external-github", "access_token"));
    return context.User.Claims.Select(x => new { x.Type, x.Value }).ToList();
}).RequireAuthorization("authenticate");

app.MapGet("/login", (HttpContext ctx) => 
    Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, 
        new List<string> {"github"}));

app.Run();