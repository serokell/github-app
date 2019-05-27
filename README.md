# Authenticate as a GitHub App

This library provides functions that help with authenticating as a [GitHub App][ghapp].


## Use

1. [Register][reg] your App with GitHub to obtain an App ID and a private key.
2. Using the data from the step above, create `AppAuth`.
3. For each installation of your app, get an `InstallationAuth` using `mkInstallationAuth`.
4. Use the `executeAppRequest` function to execute requests.
   Behind the scenes, this function exchanges the installation auth token for
   a regular access token, caches it, and renews as needed.

See [serokell/github-ops-access][ghopsa] for a real-life example use.

[ghapp]: https://developer.github.com/apps/
[reg]: https://github.com/settings/apps
[ghopsa]: https://github.com/serokell/github-ops-access/blob/test/webhook/Main.hs


## About Serokell

This library is maintained and funded with ❤️ by [Serokell](https://serokell.io/).
The names and logo for Serokell are trademark of Serokell OÜ.
