using Common.Domain;
using Common.Infrastructure;
using Common.Infrastructure.ExtensionMethods;
using Common.Infrastructure.Web;
using KRS.Abstractions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using ResearchPortal.Domain.Contacts;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ResearchPortal.ApplicationServices
{
  public class PasskeyService : ErrorManager
  {
    private readonly WebRequestProcessor _webProcessor;
    private readonly AppOptions _appOptions;
    ContactsService _contactsService;

    public PasskeyService(WebRequestProcessor webProcessor, AppOptions appOptions, ContactsService contactsService)
    {
      _webProcessor = webProcessor;
      _appOptions = appOptions;
      _contactsService = contactsService;
    }

    public async Task<string> ValidateCorbadoJWTToken(string corbadoJWTToken)//login
    {
      try
      {
        string[] tokenParts = corbadoJWTToken.Split('.');
        if (tokenParts.Length != 3)
        {
          SetDomainError(HttpStatusCode.InternalServerError, $"{corbadoJWTToken} is in an unsopported format, please contact system admin.");
          return string.Empty;
        }
        var corbadoPublicKey = await GetCorbadoPublicKey();
        if (!this.HasError || corbadoPublicKey != null)
        {
          RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
          rsa.ImportParameters(new RSAParameters()
          {
            Modulus = FromBase64Url(corbadoPublicKey.KeyValues.First().KeyProp),
            Exponent = FromBase64Url(corbadoPublicKey.KeyValues.First().Exponent)
          });
          SHA256 sha256 = SHA256.Create();
          byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));
          RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
          var algo = corbadoPublicKey.KeyValues.First().Algorythm;
          rsaDeformatter.SetHashAlgorithm("SHA256");
          if (rsaDeformatter.VerifySignature(hash, FromBase64Url(tokenParts[2])))
          {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(corbadoJWTToken);
            var sub = token.Claims.First(claim => claim.Type == "sub").Value;
            return sub;
          }
        }
        return string.Empty;
      }
      catch(Exception ex)
      {
        throw ex;
      }
    }

    private async Task<PublicKeyToken> GetCorbadoPublicKey() //called from login
    {
      try
      {
        var request = _webProcessor.CreateHttpRequest(".well-known/jwks", WebApiConstants.HttpGet, "", baseAddress: _appOptions.CorbadoPublicKeyAPI);
        var encoded = Convert.ToBase64String(Encoding.GetEncoding("ISO-8859-1").GetBytes(_appOptions.CorbadoUser + ":" + _appOptions.CorbadoKey));
        var response = await _webProcessor.ProcessHttpRequestAsync(request, Convert.ToInt32(60000), encoded);
        if (response != null)
        {
          return response.DeserializeFromJSON<PublicKeyToken>();
        }
        SetDomainError(HttpStatusCode.FailedDependency, $"Unable to retrieve Corbado public keys");
      }
      catch (Exception ex)
      {
        SetDomainError(HttpStatusCode.InternalServerError, $"Something went wrong when trying to retrieve the Corbado public keys, please contact the system administrator.");
      }
      return default;
    }

    private static byte[] FromBase64Url(string base64Url) // called from login
    {
      string padded = base64Url.Length % 4 == 0
          ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
      string base64 = padded.Replace("_", "/")
                            .Replace("-", "+");
      return Convert.FromBase64String(base64);
    }

    //this can be replaced with your own code for adding a user
    public async Task<PasskeyUser> AddCorbadoUserWithKey(string jiraKey)
    {
      int id;
      var idFound = int.TryParse(Regex.Match(jiraKey, @"\d+").Value, out id);
      Logger.LogInformation($"Found ID {id} from Key : {jiraKey}.");
      if (idFound)
      {
        var jiraUserNew = await _contactsService.GetContactById(id) as JiraContact; // this will get a user that we add to our backend
        return await AddCorbadoUserWithCheck(null, jiraUser: jiraUserNew);
      }
      return null;
    }

    //just a function for adding a suer but it checks if the user has a passkey already
    public async Task<PasskeyUser> AddCorbadoUserWithCheck(PasskeyUser user = null, JiraContact jiraUser = null) //adding user
    {
      Logger.LogInformation($"Started process.");
      if (jiraUser == null && user == null)
      {
        SetDomainError(HttpStatusCode.NoContent, "Please supply either a PasskeyUser or a JiraContact");
        return user;
      }
      if (user == null)
      {
        user = new PasskeyUser()
        {
          FirstName = jiraUser.Name,
          LastName = jiraUser.Surname,
          Email = jiraUser.Email
        };
      }
      if (string.IsNullOrEmpty(user.Email))
      {
        return user;
      }
      try
      {
        var passkeyId = await CheckIfUserExists(user, _appOptions.CorbadoUser, _appOptions.CorbadoKey, _webProcessor);
        if (string.IsNullOrEmpty(passkeyId))
        {
          passkeyId = await AddCorbadoUser(user, _appOptions.CorbadoUser, _appOptions.CorbadoKey, _webProcessor);
        }

        int retryCount = 0;
        while (jiraUser == null && retryCount < 4)
        {
          jiraUser = await _contactsService?.GetContact(user.Email) as JiraContact;
          if (jiraUser == null)
          {
            Thread.Sleep(3000);
            retryCount++;
          }
        }

        if (jiraUser?.GetAttribute(_appOptions.PasskeyUserIdAttribute)?.objectAttributeValues?.FirstOrDefault().value != passkeyId)
        {
          Logger.LogInformation($"Dev Id {user.devPasskeyID} Uat Id : {user.uatPasskeyID} Prod Id {user.prodPasskeyID} ");
          Logger.LogInformation($"Updating user on Jira");
          var resultUser = await _contactsService.UpdateContactSingleValueAttribute(jiraUser, _appOptions.PasskeyUserIdAttribute, passkeyId);
          if (resultUser != null)
          {
            Logger.LogInformation($"User updated {resultUser.Id}");
            return user;
          }
          Logger.LogInformation($"User not updated {user.Email}");
        }
      }
      catch (Exception ex)
      {
        this.SetDomainError(HttpStatusCode.NotModified, $"There was an error checking if {user.Email} exists. Error : {ex.ToString()}.");
        return null;
      }

      return user;
    }
    //checks if there is already a user on Corbado side.
    private async Task<string> CheckIfUserExists(PasskeyUser user, string APIuser, string APIKey, WebRequestProcessor webRequestProcessor) //called from adding user
    {
      try
      {
        var request = webRequestProcessor.CreateHttpRequest($"v2/identifiers?filter[]=identifierValue:eq:{user.Email}", WebApiConstants.HttpGet, null, null, _appOptions.CorbodoAPI);
        var encoded = Convert.ToBase64String(Encoding.GetEncoding("ISO-8859-1").GetBytes(APIuser + ":" + APIKey));
        var response = await webRequestProcessor.ProcessHttpRequestAsync(request, Convert.ToInt32(60000), encoded);
        var corbado = response.DeserializeFromJSON<CorbadoData>();
        if (corbado.Users.Count > 0 && !string.IsNullOrEmpty(corbado.Users.First().ID))
        {
          return corbado.Users.First().ID;
        }
        return string.Empty;
      }
      catch (Exception ex)
      {

        return null;
      }
    }
    //adds a user on Corbado side
    private async Task<string> AddCorbadoUser(PasskeyUser user, string APIuser, string APIKey, WebRequestProcessor webRequestProcessor) //called from adding user
    {
      try
      {
        var encoded = Convert.ToBase64String(Encoding.GetEncoding("ISO-8859-1").GetBytes(APIuser + ":" + APIKey));
        var parms = new
        {
          fullname = user.FullName,
          status = "active"
        };
        var parmsJson = JsonConvert.SerializeObject(parms);
        var request = webRequestProcessor.CreateHttpRequest($"v2/users", WebApiConstants.HttpPost, parmsJson, null, _appOptions.CorbodoAPI);
        var response = await webRequestProcessor.ProcessHttpRequestAsync(request, Convert.ToInt32(60000), encoded);
        var corbadoResponse = response.DeserializeFromJSON<CorbadoObject>();
        if (corbadoResponse != null && !string.IsNullOrEmpty(corbadoResponse.UserID))
        {
          var identifierParms = new
          {
            identifierType = $"email",
            identifierValue = user.Email,
            status = "verified"
          };
          parmsJson = JsonConvert.SerializeObject(identifierParms);
          var identifierRequest = webRequestProcessor.CreateHttpRequest($"v2/users/{corbadoResponse.UserID}/identifiers", WebApiConstants.HttpPost, parmsJson, null, _appOptions.CorbodoAPI);
          var finalResponse = await webRequestProcessor.ProcessHttpRequestAsync(identifierRequest, Convert.ToInt32(60000), encoded);
          var finalCorbadoReponse = finalResponse.DeserializeFromJSON<CorbadoObject>();
          return corbadoResponse.UserID;
        }
      }
      catch (Exception ex)
      {
        this.SetDomainError(HttpStatusCode.InternalServerError, $"{user.Email} there was an error in user creation on Corbado, please verify on Corbado Dashboard. Error: {ex.Message}.");
      }
      return "User Creation Not Successfull";
    }
  }
}
