# WinAuthenticator

WinAuthenticator allows to authenticate to Jupyterhub using local Windows accounts. It creates an authentication token, which is stored in the **auth_token** field of [auth_state](http://jupyterhub.readthedocs.io/en/latest/reference/authenticators.html). Custom spawners can use this token to spawn processes as the authenticated user ([WinLocalProcessSpawner](https://github.com/ni/jupyterhub-winlocalprocessspawner) uses this method).

WinAuthenticator will try to load the user profile after authentication, in order to load the per-user environment variables needed to create a proper sandbox. This operation requires "Local System" access. If the account launching Jupyterhub doesn't have "Local System" access, the user profile load operation will fail and the notebook servers will be launched in a temp folder instead.

# Installation

Currenty, there is no pip package, so you need to install the winauthenticator by cloning the repo.

```
git clone https://github.com/ni/jupyterhub-winauthenticator.git
cd jupyterhub-winauthenticator
pip3 install -e
```

# Usage

To enable, add the following to your jupyterhub file:

```
c.JupyterHub.authenticator_class = 'winauthenticator.WinAuthenticator'
```

# Required configuration

Since the WinAuthenticator stores the auth token in the auth_state, it needs to be enabled.

```
c.WinAuthenticator.enable_auth_state = True
```

# Optional Configuration

```
c.WinAuthenticator.open_sessions
```

Wheter to load a Windows user profile. 

Loading a user profile will load the per user APPDATA and USERPROFILE environment variables, which will be used to define the notebook server CWD (USERPROFILE) and jupyter runtime folder (APPDATA). If this is set to False, the CWD is set to a temp folder (which is created). The jupyter runtime folder is set to the jupyterhub process APPDATA. Default is True.

If any errors are encounters when opening, this is automatically set to False

# Running

Since WinAuthenticator uses **auth_state**, Jupyterhub requires that the environment variable **JUPYTERHUB_CRYPT_KEY** is defined and set to a hex-encoded 32-byte key (you can get a key by running "openssl rand -hex 32").

