# ScsSaveCacheBuster

In 1.50 SCS made changes to how the filesystem works which had a side effect of save files always loading a cached version after being loaded once.
This makes editing the save file very annoying with having to save the file again before being able to make more changes.

This plugin makes it so the save file is removed from the cache before it gets loaded so it will load the actual file.

### How to use

> [!NOTE]
> Use at own risk, this has not been tested very thoroughly yet, it could always have some hidden issues.

You can download the plugin from [here](https://github.com/dariowouters/ScsSaveCacheBuster/releases/latest).
With the game closed place the `ScsSaveCacheBuster.dll` in `<game_install_location>/bin/win_x64/plugins`
(if the plugins folder does not exists, you can create one)

Then whenever you load a save that is cached it will automatically remove it from the cache first.
