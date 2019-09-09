using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace JwtAuthDemo.Controllers
{
    [Authorize]
    public class UserController : ApiController
    {
        public IHttpActionResult Get()
        {
            return Ok(new { User.Identity.Name });
        }
    }
}