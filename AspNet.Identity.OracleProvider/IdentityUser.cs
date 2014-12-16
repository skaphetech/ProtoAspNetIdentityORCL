// Copyright (c) Timm Krause. All rights reserved. See LICENSE file in the project root for license information.

namespace AspNet.Identity.OracleProvider
{
    using System;
    using Microsoft.AspNet.Identity;

    public class IdentityUser : IUser
    {
        public IdentityUser()
        {
            Id = Guid.NewGuid().ToString();
        }

        public IdentityUser(string userName)
            : this()
        {
            UserName = userName;
        }

        public string Id { get; set; }

        public string UserName { get; set; }

        public string Email { get; set; }

        public bool EmailConfirmed { get; set; }

        public string PasswordHash { get; set; }

        public string SecurityStamp { get; set; }

        public bool LockoutEnabled { get; set; }

        public int AccessFailedCount { get; set; }

        public virtual DateTime? LockoutEndDateUtc { get; set; }

        public bool TwoFactorEnabled { get; set; }

        public string PhoneNumber { get; set; }

        public bool PhoneNumberConfirmed { get; set; }


    }
}
