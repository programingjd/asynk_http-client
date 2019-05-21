![jcenter](https://img.shields.io/badge/_jcenter_-0.0.0.31-6688ff.png?style=flat) &#x2003; ![jcenter](https://img.shields.io/badge/_Tests_-21/21-green.png?style=flat)
# Asynk HTTP Client
An HTTP async client with suspend functions for kotlin coroutines.

## Download ##

The maven artifacts are on [Bintray](https://bintray.com/programingjd/maven/info.jdavid.asynk.http-client/view)
and [jcenter](https://bintray.com/search?query=info.jdavid.asynk.http-client).

[Download](https://bintray.com/artifact/download/programingjd/maven/info/jdavid/asynk/http-client/0.0.0.31/http-client-0.0.0.31.jar) the latest jar.

__Maven__

Include [those settings](https://bintray.com/repo/downloadMavenRepoSettingsFile/downloadSettings?repoPath=%2Fbintray%2Fjcenter)
 to be able to resolve jcenter artifacts.
```
<dependency>
  <groupId>info.jdavid.asynk</groupId>
  <artifactId>http-client</artifactId>
  <version>0.0.0.31</version>
</dependency>
```
__Gradle__

Add jcenter to the list of maven repositories.
```
repositories {
  jcenter()
}
```
```
dependencies {
  compile 'info.jdavid.asynk:http-client:0.0.0.31'
}
```