import asyncio
from concurrent.futures import ThreadPoolExecutor
from tornado.concurrent import run_on_executor
from traitlets import default, Any, Bool

from jupyterhub.auth import LocalAuthenticator, Authenticator
from jupyterhub.utils import maybe_future

import win32security
import pywintypes
import win32profile
import win32net

class WinAuthenticator(LocalAuthenticator):
    """Authenticate local Windows users"""

    # Variable to store registry hive handle, which is not being loaded. It needs to be
    # stored since UnloadUserProfiles requires a live registry hive handle to succeed.
    _hreg = None

    # run Windows Auth in a thread, since it can be slow
    executor = Any()
    @default('executor')
    def _default_executor(self):
        return ThreadPoolExecutor(1)

    open_sessions = Bool(True,
                         help="""
        Whether to load a user profile when spawners are started.
        This may trigger things like creating USERPROFILE and APPDATA directories
        If any errors are encountered when loading/unloading user profiles,
        this is automatically set to False.
        """
                        ).tag(config=True)


    @default('add_user_cmd')
    def _add_user_cmd_default(self):
        """Guess the most likely-to-work adduser command for each platform"""
        raise NotImplementedError("I don't know how to create users on Windows")

    def normalize_username(self, username):
        """Normalize the given username and return it
        Apply `username_map` if it is set.
        """
        username = self.username_map.get(username, username)
        return username

    async def add_user(self, user):
        """Hook called whenever a new user is added
        self.create_system_users not supported.
        """
        islocaluser = '@' not in user.name
        user_exists = await maybe_future(self.system_user_exists(user))
        if not user_exists and islocaluser:
            if self.create_system_users:
                raise KeyError("There is no support for create_system_users on Windows")
            else:
                raise KeyError("User %s does not exist." % user.name)

        await maybe_future(Authenticator.add_user(self, user))

    @staticmethod
    def system_user_exists(user):
        """Check if the user exists on the system"""
        local_users = win32net.NetUserEnum(None, 0)[0]
        for local_user in local_users:
            if local_user['name'] == user.name:
                return True
        return False

    def check_group_whitelist(self, username):
        """
        If group_whitelist is configured, check if authenticating user is part of group.
        """
        if not self.group_whitelist:
            return False
        for group in self.group_whitelist:
            try:
                members = win32net.NetLocalGroupGetMembers(None, group, 1)
            except Exception as exc:
                self.log.warning("Failed to get group members for %s: %s", group, exc)
                continue
            for member in members[0]:
                if username == member['name']:
                    return True
        return False

    @run_on_executor
    def authenticate(self, handler, data):
        """Authenticate with Windows, and return the username if login is successful.
        Return None otherwise.
        """
        domain = '.'
        username = data['username']

        if '@' in data['username']:
            username, domain = username.split('@')

        try:
            token = win32security.LogonUser(
                username,
                domain,
                data['password'],
                win32security.LOGON32_LOGON_NETWORK,
                win32security.LOGON32_PROVIDER_DEFAULT)
        except win32security.error:
            # Invalid User
            return None

        # Incorrect Password
        if not token:
            return None
        return {
            'name': data['username'],
            'auth_state': {
                # Detach so the underlying winhandle stays alive
                'auth_token': token.Detach(),
            },
        }

    @run_on_executor
    def pre_spawn_start(self, user, spawner):
        """Load profile for user if so configured"""

        token = None
        profilepath = None

        if not self.open_sessions:
            return
        try:
            loop = asyncio.new_event_loop()
            auth_state = loop.run_until_complete(user.get_auth_state())
            token = pywintypes.HANDLE(auth_state['auth_token'])

            if '@' not in user.name:
                # Check if user has a roaming Profile
                user_info = win32net.NetUserGetInfo(None, user.name, 4)
                profilepath = user_info['profile']

            # Loading the profile will create the USERPROFILE and APPDATA folders,
            # if not present. To load the profile, the running process needs to have
            # the SE_RESTORE_NAME and SE_BACKUP_NAME privileges.
            self._hreg = win32profile.LoadUserProfile(
                token,
                {'UserName':user.name, 'ProfilePath':profilepath}
            )
        except Exception as exc:
            self.log.warning("Failed to load user profile for %s: %s", user.name, exc)
            self.log.warning("Disabling user profile from now on.")
            self.open_sessions = False
        finally:
            if token:
                # Detach so the underlying winhandle stays alive
                token.Detach()

    @run_on_executor
    def post_spawn_stop(self, user, spawner):
        """Unload profile for user if we were configured to opened one"""

        token = None

        if not self.open_sessions:
            return
        try:
            loop = asyncio.new_event_loop()
            auth_state = loop.run_until_complete(user.get_auth_state())
            token = pywintypes.HANDLE(auth_state['auth_token'])
            win32profile.UnloadUserProfile(token, self._hreg)
        except Exception as exc:
            self.log.warning("Failed to unload user profile for %s: %s", user.name, exc)
            self.log.warning("Disabling user profile from now on.")
            self.open_sessions = False
        finally:
            if token:
                # Detach so token stays valid
                token.Detach()
