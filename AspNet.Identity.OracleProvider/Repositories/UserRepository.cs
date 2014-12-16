﻿// Copyright (c) Timm Krause. All rights reserved. See LICENSE file in the project root for license information.

namespace AspNet.Identity.OracleProvider.Repositories
{
    using System;
    using System.Collections.Generic;
    using System.Data;
    using System.Linq;
    using Oracle.ManagedDataAccess.Client;

    internal class UserRepository
    {
        private readonly OracleDataContext _db;

        public UserRepository(OracleDataContext oracleContext)
        {
            _db = oracleContext;
        }

        public int Insert(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return _db.ExecuteNonQuery(
                "INSERT INTO users (id, username, passwordhash, securitystamp, email, emailconfirmed, " +
                " lockoutenabled, accessfailedcount, lockoutenddateutc,twofactorenabled,phonenumber,phonenumberconfirmed) VALUES " +
                "(:id, :name, :passwordhash, :securitystamp, :email, :emailconfirmed, :lockoutenabled," +
                " :accessfailedcount, :lockoutenddateutc, :twofactorenabled, :phonenumber, :phonenumberconfirmed)",
                new OracleParameter { ParameterName = ":id", Value = user.Id, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":name", Value = user.UserName, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":passwordhash", Value = user.PasswordHash, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":securitystamp", Value = user.SecurityStamp, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":email", Value = user.Email, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":emailconfirmed", Value = user.EmailConfirmed ? 1 : 0, OracleDbType = OracleDbType.Int16, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":lockoutenabled", Value = user.LockoutEnabled ? 1 : 0, OracleDbType = OracleDbType.Int16, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":accessfailedcount", Value = user.AccessFailedCount, OracleDbType = OracleDbType.Int16, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":lockoutenddateutc", Value = user.LockoutEndDateUtc == null ? new DateTime() : user.LockoutEndDateUtc, OracleDbType = OracleDbType.Date, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":twofactorenabled", Value = user.TwoFactorEnabled ? 1 : 0, OracleDbType = OracleDbType.Int16, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":phonenumber", Value = user.PhoneNumber, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":phonenumberconfirmed", Value = user.PhoneNumberConfirmed ? 1 : 0, OracleDbType = OracleDbType.Int16, Direction = ParameterDirection.Input });
        }

        public int Update(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            //lockoutenddateutc = :lockoutenddateutc,
            return _db.ExecuteNonQuery(
                "UPDATE users SET username = :userName, passwordhash = :passwordhash, securitystamp = :securitystamp, email = :email, " +
                "emailconfirmed = :emailconfirmed, lockoutenabled = :lockoutenabled, accessfailedcount = :accessfailedcount, " +
                "twofactorenabled = :twofactorenabled, phonenumber = :phonenumber, " +
                "phonenumberconfirmed = :phonenumberconfirmed WHERE id = :userid",
                new OracleParameter { ParameterName = ":username", Value = user.UserName, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":passwordhash", Value = user.PasswordHash, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":securitystamp", Value = user.SecurityStamp, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":userid", Value = user.Id, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":email", Value = user.Email, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":emailconfirmed", Value = user.EmailConfirmed ? 1 : 0, OracleDbType = OracleDbType.Int16, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":lockoutenabled", Value = user.LockoutEnabled ? 1 : 0, OracleDbType = OracleDbType.Int16, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":accessfailedcount", Value = user.AccessFailedCount == null ? 0 : user.AccessFailedCount, OracleDbType = OracleDbType.Int16, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":twofactorenabled", Value = user.TwoFactorEnabled ? 1 : 0, OracleDbType = OracleDbType.Int16, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":phonenumber", Value = user.PhoneNumber == null ? "" : user.PhoneNumber, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
                new OracleParameter { ParameterName = ":phonenumberconfirmed", Value = user.PhoneNumberConfirmed ? 1 : 0, OracleDbType = OracleDbType.Int16, Direction = ParameterDirection.Input });

            //new OracleParameter { ParameterName = ":lockoutenddateutc", Value = user.LockoutEndDateUtc == null ? new DateTime() : user.LockoutEndDateUtc, OracleDbType = OracleDbType.Date, Direction = ParameterDirection.Input },
        }

        public int Delete(string userId)
        {
            return _db.ExecuteNonQuery(
                "DELETE FROM users WHERE id = :userid",
                new OracleParameter { ParameterName = ":userid", Value = userId, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input });
        }

        public int Delete(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Delete(user.Id);
        }

        ////public string GetUserName(string userId)
        ////{
        ////    return _db.ExecuteScalarQuery<string>(
        ////        "SELECT name FROM users WHERE id = :id",
        ////        new OracleParameter { ParameterName = ":id", Value = userId, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input });
        ////}

        ////public string GetUserId(string userName)
        ////{
        ////    return _db.ExecuteScalarQuery<string>(
        ////       "SELECT id FROM users WHERE username = :name",
        ////       new OracleParameter { ParameterName = ":name", Value = userName, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input });
        ////}

        public IdentityUser GetUserById(string userId)
        {
            var result = _db.ExecuteQuery(
              "SELECT * FROM users WHERE id = :id",
              new OracleParameter { ParameterName = ":id", Value = userId, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input });

            var row = result.Rows.Cast<DataRow>().SingleOrDefault();

            if (row != null)
            {
                return new IdentityUser
                {
                    Id = row["id"].ToString(),
                    UserName = row["username"].ToString(),
                    PasswordHash = row["passwordhash"].ToString().HasValue() ? row["passwordhash"].ToString() : null,
                    SecurityStamp = row["securitystamp"].ToString().HasValue() ? row["securitystamp"].ToString() : null
                };
            }

            return null;
        }

        public ICollection<IdentityUser> GetUserByName(string userName)
        {
            var result = _db.ExecuteQuery(
                "SELECT * FROM users WHERE username = :name",
                new OracleParameter { ParameterName = ":name", Value = userName, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input });

            return result.Rows.Cast<DataRow>().Select(
                r => new IdentityUser
                {
                    Id = r["id"].ToString(),
                    UserName = r["username"].ToString(),
                    PasswordHash = r["passwordhash"].ToString().HasValue() ? r["passwordhash"].ToString() : null,
                    SecurityStamp = r["securitystamp"].ToString().HasValue() ? r["securitystamp"].ToString() : null
                }).ToList();
        }

        public string GetPasswordHash(string userId)
        {
            var passwordHash = _db.ExecuteScalarQuery<string>(
                "SELECT passwordhash FROM users WHERE id = :id",
                new OracleParameter { ParameterName = ":id", Value = userId, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input });

            return passwordHash.HasValue() ? passwordHash : null;
        }

        public IdentityUser GetUserByEmail(string email)
        {
            return null;
        }

        ////public int SetPasswordHash(string userId, string passwordHash)
        ////{
        ////    return _db.ExecuteScalarQuery<int>(
        ////        "UPDATE users SET passwordhash = :passwordhash WHERE id = :id",
        ////        new OracleParameter { ParameterName = ":passwordhash", Value = passwordHash, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input },
        ////        new OracleParameter { ParameterName = ":id", Value = userId, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input });
        ////}

        ////public string GetSecurityStamp(string userId)
        ////{
        ////    return _db.ExecuteScalarQuery<string>(
        ////        "SELECT securitystamp FROM users WHERE id = :id",
        ////        new OracleParameter { ParameterName = ":id", Value = userId, OracleDbType = OracleDbType.Varchar2, Direction = ParameterDirection.Input });
        ////}
    }
}
