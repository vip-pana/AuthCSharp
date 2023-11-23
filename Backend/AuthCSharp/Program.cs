using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
namespace TodoApi;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        var registeredUsers = new List<User> { };

        app.MapPost("/signin", ([FromBody] SignInUser signInUser) =>
        {
            // Validate the user
            if (signInUser != null)
            {
                var modelError = ValidationSignIn(signInUser: signInUser);

                if (modelError.Any())
                {
                    return Results.BadRequest(modelError);
                }
                else
                {
                    var hashPassword = BCrypt.Net.BCrypt.EnhancedHashPassword(signInUser.Password);

                    User user = new User()
                    {
                        FirstName = signInUser.FirstName,
                        LastName = signInUser.LastName,
                        Mail = signInUser.Mail,
                        Password = hashPassword
                    };

                    registeredUsers.Add(user);

                    return Results.Created("/signin", signInUser);
                }
            }
            else
            {
                return Results.BadRequest("User not inserted.");
            }
        });

        app.MapPost("/login", ([FromBody] LoginUser loginUser) =>
        {
            if (loginUser != null)
            {
                List<string> modelError = ValidationLogin(loginUser);

                if (modelError.Any())
                {
                    return Results.BadRequest(modelError);
                }
                else
                {
                    var registeredUser = registeredUsers.Where(i => i.Mail.Equals(loginUser.Mail)).FirstOrDefault();

                    if (registeredUser == null)
                    {
                        modelError.Add("no user found.");
                        return Results.BadRequest(modelError);
                    }
                    else
                    {
                        if (BCrypt.Net.BCrypt.EnhancedVerify(loginUser.Password, registeredUser.Password))
                        {
                            return Results.Accepted("Login effettuato.");
                        }
                        else
                        {
                            return Results.BadRequest("Password errata.");
                        }
                    }
                }
            }
            else
            {
                return Results.BadRequest("User not inserted.");
            }
        });

        app.Run();
    }

    private static List<string> ValidationLogin(LoginUser loginUser)
    {
        var modelError = new List<string>();

        if (string.IsNullOrEmpty(loginUser.Mail) || !loginUser.Mail.Contains("@") || !loginUser.Mail.Contains("."))
        {
            modelError.Add("Mail not inserted or bad wrote");
        }
        if (string.IsNullOrEmpty(loginUser.Password))
        {
            modelError.Add("Password not inserted");
        }

        return modelError;
    }

    public static List<string> ValidationSignIn(SignInUser signInUser)
    {
        var modelError = new List<string>();

        var regexPattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,15}$";
        Regex regex = new Regex(regexPattern);

        if (string.IsNullOrEmpty(signInUser.FirstName))
        {
            modelError.Add("FirstName not inserted.");
        }

        if (string.IsNullOrEmpty(signInUser.LastName))
        {
            modelError.Add("LastName not inserted.");
        }

        if (string.IsNullOrEmpty(signInUser.Mail) || !signInUser.Mail.Contains("@") || !signInUser.Mail.Contains("."))
        {
            modelError.Add("Mail not inserted or bad wrote.");
        }

        if (string.IsNullOrEmpty(signInUser.Password) || !signInUser.Password.Equals(signInUser.ConfirmPassword))
        {
            modelError.Add("Password not inserted or not correct.");
        }
        else
        {
            if (!regex.IsMatch(signInUser.Password))
            {
                modelError.Add("At least one lowercase letter, one uppercase letter, and one digit in a password, and it also requires the password to be between 8 and 15 characters long");
            }
        }

        return modelError;
    }
}
