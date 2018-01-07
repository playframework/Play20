/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package javaguide.ehcache.qualified;

//#qualified
import play.cache.*;
import play.mvc.*;

import javax.inject.Inject;

public class Application extends Controller {

    @Inject @NamedCache("session-cache") SyncCacheApi cache;

    // ...
}
//#qualified
