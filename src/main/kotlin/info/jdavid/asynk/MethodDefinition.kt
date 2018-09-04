package info.jdavid.asynk

import info.jdavid.asynk.http.Method

sealed class MethodDefinition(private val method: Method): RequestDefinition<MethodDefinition>()

abstract class MethodDefinitionBodyRequired internal constructor(method: Method): MethodDefinition(method) {}
abstract class MethodDefinitionBodyAllowed internal constructor(method: Method): MethodDefinition(method) {}
abstract class MethodDefinitionBodyDisallowed internal constructor(method: Method): MethodDefinition(method) {}

class Options: MethodDefinitionBodyDisallowed(Method.OPTIONS)
class Head: MethodDefinitionBodyDisallowed(Method.HEAD)
class Get: MethodDefinitionBodyDisallowed(Method.GET)
class Delete: MethodDefinitionBodyAllowed(Method.DELETE)
class Post: MethodDefinitionBodyRequired(Method.POST)
class Put: MethodDefinitionBodyRequired(Method.PUT)
class Patch: MethodDefinitionBodyRequired(Method.PATCH)
class Method(name: String): MethodDefinitionBodyAllowed(Method.from(name))
