# 3dmloader-Package

A little rewrite of traditional 3dmigoto loader exe with support for endfield and overtime more customizable!
Also written in rust because `rewrite it in rust`

## Environment variables
- `LOADER_MODE` can be set to either `inject` or `hook` not setting the variable or setting it to anything other than `inject` fallbacks to `hook`
- Everything else is pulled from `d3dx.ini` file