// Copyright (c) Timm Krause. All rights reserved. See LICENSE file in the project root for license information.

namespace AspNet.Identity.OracleProvider
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;
    using Repositories;

    public class UserStore :
        IUserStore<IdentityUser>,
        IUserClaimStore<IdentityUser>,
        IUserLoginStore<IdentityUser>,
        IUserRoleStore<IdentityUser>,
        IUserPasswordStore<IdentityUser>,
        IUserEmailStore<IdentityUser>,
        IUserLockoutStore<IdentityUser, string>,
        IUserTwoFactorStore<IdentityUser, string>
    {
        private readonly UserRepository _userRepository;
        private readonly UserClaimsRepository _userClaimsRepository;
        private readonly UserLoginsRepository _userLoginsRepository;
        private readonly RoleRepository _roleRepository;
        private readonly UserRolesRepository _userRolesRepository;

        public IQueryable<IdentityUser> Users
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public UserStore()
            : this(new OracleDataContext())
        {
        }

        public UserStore(OracleDataContext database)
        {
            // TODO: Compare with EntityFramework provider.
            Database = database;

            _userRepository = new UserRepository(database);
            _roleRepository = new RoleRepository(database);
            _userRolesRepository = new UserRolesRepository(database);
            _userClaimsRepository = new UserClaimsRepository(database);
            _userLoginsRepository = new UserLoginsRepository(database);
        }
                
        public OracleDataContext Database { get; private set; }

        public Task CreateAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            _userRepository.Insert(user);

            return Task.FromResult<object>(null);
        }

        public Task DeleteAsync(IdentityUser user)
        {
            if (user != null)
            {
                _userRepository.Delete(user);
            }

            return Task.FromResult<object>(null);
        }

        public Task<IdentityUser> FindByIdAsync(string userId)
        {
            if (userId.HasNoValue())
            {
                throw new ArgumentException("userId");
            }

            var result = _userRepository.GetUserById(userId);

            return Task.FromResult(result);
        }

        public Task<IdentityUser> FindByNameAsync(string userName)
        {
            if (userName.HasNoValue())
            {
                throw new ArgumentException("userName");
            }

            var result = _userRepository.GetUserByName(userName).SingleOrDefault();

            return Task.FromResult(result);
        }

        public Task UpdateAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            _userRepository.Update(user);

            return Task.FromResult<object>(null);
        }

        public Task AddClaimAsync(IdentityUser user, Claim claim)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }

            _userClaimsRepository.Insert(claim, user.Id);

            return Task.FromResult<object>(null);
        }

        public Task<IList<Claim>> GetClaimsAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var claimsIdentity = _userClaimsRepository.FindByUserId(user.Id);

            return Task.FromResult<IList<Claim>>(claimsIdentity.Claims.ToList());
        }

        public Task RemoveClaimAsync(IdentityUser user, Claim claim)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }

            _userClaimsRepository.Delete(user, claim);

            return Task.FromResult<object>(null);
        }

        public Task AddLoginAsync(IdentityUser user, UserLoginInfo login)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            _userLoginsRepository.Insert(user, login);

            return Task.FromResult<object>(null);
        }

        public Task<IdentityUser> FindAsync(UserLoginInfo login)
        {
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            var userId = _userLoginsRepository.FindUserIdByLogin(login);

            if (userId != null)
            {
                var user = _userRepository.GetUserById(userId);

                if (user != null)
                {
                    return Task.FromResult(user);
                }
            }

            return Task.FromResult<IdentityUser>(null);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var userLogins = _userLoginsRepository.FindByUserId(user.Id);

            return Task.FromResult(userLogins);
        }

        public Task RemoveLoginAsync(IdentityUser user, UserLoginInfo login)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (login == null)
            {
                throw new ArgumentNullException("login");
            }

            _userLoginsRepository.Delete(user, login);

            return Task.FromResult<object>(null);
        }

        public Task AddToRoleAsync(IdentityUser user, string role)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (role.HasNoValue())
            {
                throw new ArgumentNullException("role");
            }

            var roleId = _roleRepository.GetRoleId(role);

            if (roleId.HasValue())
            {
                _userRolesRepository.Insert(user, roleId);
            }

            return Task.FromResult<object>(null);
        }

        public Task<IList<string>> GetRolesAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var roles = _userRolesRepository.FindByUserId(user.Id);

            return Task.FromResult(roles);
        }

        public Task<bool> IsInRoleAsync(IdentityUser user, string role)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (role.HasNoValue())
            {
                throw new ArgumentNullException("role");
            }

            var roles = _userRolesRepository.FindByUserId(user.Id);

            return Task.FromResult(roles != null && roles.Contains(role));
        }

        public Task RemoveFromRoleAsync(IdentityUser user, string role)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (role.HasNoValue())
            {
                throw new ArgumentNullException("role");
            }

            var roleId = _roleRepository.GetRoleId(role);

            if (roleId.HasValue())
            {
                _userRolesRepository.Delete(user, roleId);
            }

            return Task.FromResult<object>(null);
        }

        public Task<string> GetPasswordHashAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var passwordHash = _userRepository.GetPasswordHash(user.Id);

            return Task.FromResult(passwordHash);
        }

        public Task<bool> HasPasswordAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var hasPassword = _userRepository.GetPasswordHash(user.Id).HasValue();

            return Task.FromResult(hasPassword);
        }

        public Task SetPasswordHashAsync(IdentityUser user, string passwordHash)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.PasswordHash = passwordHash;

            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// Set email on user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="email"></param>
        /// <returns></returns>
        public Task SetEmailAsync(IdentityUser user, string email)
        {
            user.Email = email;
            _userRepository.Update(user);

            return Task.FromResult(0);

        }

        /// <summary>
        /// Get email from user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<string> GetEmailAsync(IdentityUser user)
        {
            return Task.FromResult(user.Email);
        }

        /// <summary>
        /// Get if user email is confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<bool> GetEmailConfirmedAsync(IdentityUser user)
        {
            return Task.FromResult(user.EmailConfirmed);
        }

        /// <summary>
        /// Set when user email is confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <param name="confirmed"></param>
        /// <returns></returns>
        public Task SetEmailConfirmedAsync(IdentityUser user, bool confirmed)
        {
            // var userLogins = _userLoginsRepository.FindByUserId(user.Id);
            user.EmailConfirmed = confirmed;
            _userRepository.Update(user);

            return Task.FromResult(0);
        }

        /// <summary>
        /// Get user by email
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public Task<IdentityUser> FindByEmailAsync(string email)
        {
            if (String.IsNullOrEmpty(email))
            {
                throw new ArgumentNullException("email");
            }

            IdentityUser result = _userRepository.GetUserByEmail(email);
            if (result != null)
            {
                return Task.FromResult<IdentityUser>(result);
            }

            return Task.FromResult<IdentityUser>(null);
        }


        /// <summary>
        /// Get if lockout is enabled for the user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<bool> GetLockoutEnabledAsync(IdentityUser user)
        {
            return Task.FromResult(user.LockoutEnabled);
        }

        /// <summary>
        /// Set lockout enabled for user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        public Task SetLockoutEnabledAsync(IdentityUser user, bool enabled)
        {
            user.LockoutEnabled = enabled;
            //_userRepository.Update(user);

            return Task.FromResult(0);
        }

        /// <summary>
        /// Get failed access count
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<int> GetAccessFailedCountAsync(IdentityUser user)
        {
            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>
        /// Reset failed access count
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task ResetAccessFailedCountAsync(IdentityUser user)
        {
            user.AccessFailedCount = 0;
            _userRepository.Update(user);

            return Task.FromResult(0);
        }


        /// <summary>
        /// Increment failed access count
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<int> IncrementAccessFailedCountAsync(IdentityUser user)
        {
            user.AccessFailedCount++;
            _userRepository.Update(user);

            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>
        /// Get user lock out end date
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<DateTimeOffset> GetLockoutEndDateAsync(IdentityUser user)
        {
            return
                Task.FromResult(user.LockoutEndDateUtc.HasValue
                    ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc))
                    : new DateTimeOffset());
        }

        /// <summary>
        /// Set user lockout end date
        /// </summary>
        /// <param name="user"></param>
        /// <param name="lockoutEnd"></param>
        /// <returns></returns>
        public Task SetLockoutEndDateAsync(IdentityUser user, DateTimeOffset lockoutEnd)
        {
            user.LockoutEndDateUtc = lockoutEnd.UtcDateTime;
            _userRepository.Update(user);

            return Task.FromResult(0);
        }

        /// <summary>
        /// Set user phone number
        /// </summary>
        /// <param name="user"></param>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        public Task SetPhoneNumberAsync(IdentityUser user, string phoneNumber)
        {
            user.PhoneNumber = phoneNumber;
            _userRepository.Update(user);

            return Task.FromResult(0);
        }

        /// <summary>
        /// Get user phone number
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<string> GetPhoneNumberAsync(IdentityUser user)
        {
            return Task.FromResult(user.PhoneNumber);
        }

        /// <summary>
        /// Get if user phone number is confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<bool> GetPhoneNumberConfirmedAsync(IdentityUser user)
        {
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        /// <summary>
        /// Set phone number if confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <param name="confirmed"></param>
        /// <returns></returns>
        public Task SetPhoneNumberConfirmedAsync(IdentityUser user, bool confirmed)
        {
            user.PhoneNumberConfirmed = confirmed;
            _userRepository.Update(user);

            return Task.FromResult(0);
        }

        /// <summary>
        /// Set two factor authentication is enabled on the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        public Task SetTwoFactorEnabledAsync(IdentityUser user, bool enabled)
        {
            user.TwoFactorEnabled = enabled;
            _userRepository.Update(user);

            return Task.FromResult(0);
        }

        /// <summary>
        /// Get if two factor authentication is enabled on the user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<bool> GetTwoFactorEnabledAsync(IdentityUser user)
        {
            return Task.FromResult(user.TwoFactorEnabled);
        }

        /// <summary>
        ///  Set security stamp
        /// </summary>
        /// <param name="user"></param>
        /// <param name="stamp"></param>
        /// <returns></returns>
        public Task SetSecurityStampAsync(IdentityUser user, string stamp)
        {
            user.SecurityStamp = stamp;

            return Task.FromResult(0);

        }

        /// <summary>
        /// Get security stamp
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<string> GetSecurityStampAsync(IdentityUser user)
        {
            return Task.FromResult(user.SecurityStamp);
        }

               
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (Database != null)
                {
                    Database.Dispose();
                    Database = null;
                }
            }
        }
    }
}
