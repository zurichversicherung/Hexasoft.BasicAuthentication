using NetTools;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;

namespace Hexasoft
{
    public class BasicAuthentication : IHttpModule
    {
        public void Init(HttpApplication context)
        {
            context.BeginRequest += ContextBeginRequest;
        }

        private void ContextBeginRequest(object sender, EventArgs e)
        {
            if (Bypassed())
                return;

            if (Required())
            {
                if (!ValidateCredentials())
                {
                    var httpApplication = (HttpApplication)sender;
                    httpApplication.Context.Response.Clear();
                    httpApplication.Context.Response.Status = "401 Unauthorized";
                    httpApplication.Context.Response.StatusCode = 401;
                    httpApplication.Context.Response.AddHeader("WWW-Authenticate", "Basic realm=\"" + Request.Url.Host + "\"");
                    httpApplication.CompleteRequest();
                }
            }
        }

        private bool Bypassed()
        {
            var ip = GetIPAddress();

            if (ip == null)
                return false;

            string ipRangeBypassSetting = ConfigurationManager.AppSettings["BasicAuthentication.IpRangeBypassList"];

            if (string.IsNullOrEmpty(ipRangeBypassSetting))
                return false;

            IEnumerable<IPAddressRange> ipRanges = ipRangeBypassSetting.Split('|', ';')
                .Select(n => IPAddressRange.TryParse(n, out var ipRange) ? ipRange : null)
                .Where(n => n != null);

            return ipRanges.Any(n => n.Contains(ip));
        }

        protected IPAddress GetIPAddress()
        {
            System.Web.HttpContext context = System.Web.HttpContext.Current;
            string ipAddress = context.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];

            if (!string.IsNullOrEmpty(ipAddress))
            {
                string[] addresses = ipAddress.Split(',');
                if (addresses.Length != 0 && IPAddress.TryParse(addresses[0], out var ip1))
                {
                    return ip1;
                }
            }

            return IPAddress.TryParse(context.Request.ServerVariables["REMOTE_ADDR"], out var ip2) ? ip2 : null;
        }

        private bool Required()
        {
            bool required = false;
            string requiredSetting = ConfigurationManager.AppSettings["BasicAuthentication.Required"];

            if (!string.IsNullOrWhiteSpace(requiredSetting))
            {
                requiredSetting = requiredSetting.Trim().ToLower();
                required = requiredSetting == "1" || requiredSetting == "true";
            }

            return required;
        }

        private bool ValidateCredentials()
        {
            string validUsername = ConfigurationManager.AppSettings["BasicAuthentication.Username"];

            if (string.IsNullOrEmpty(validUsername))
                return false;

            string validPassword = ConfigurationManager.AppSettings["BasicAuthentication.Password"];

            if (string.IsNullOrEmpty(validPassword))
                return false;

            string header = Request.Headers["Authorization"];

            if (string.IsNullOrEmpty(header))
                return false;

            header = header.Trim();
            if (header.IndexOf("Basic ", StringComparison.InvariantCultureIgnoreCase) != 0)
                return false;

            string credentials = header.Substring(6);

            // Decode the Base64 encoded credentials
            byte[] credentialsBase64DecodedArray = Convert.FromBase64String(credentials);
            string decodedCredentials = Encoding.UTF8.GetString(credentialsBase64DecodedArray, 0, credentialsBase64DecodedArray.Length);

            // Get username and password
            int separatorPosition = decodedCredentials.IndexOf(':');

            if (separatorPosition <= 0)
                return false;

            string username = decodedCredentials.Substring(0, separatorPosition);
            string password = decodedCredentials.Substring(separatorPosition + 1);

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                return false;

            return username.ToLower() == validUsername.ToLower() && password == validPassword;
        }

        private HttpRequest Request
        {
            get
            {
                return HttpContext.Current.Request;
            }
        }

        public void Dispose()
        {
        }
    }
}