/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */

package javaguide.di.field;

//#field
import javax.inject.*;
import play.libs.ws.*;

public class MyComponent {
    @Inject WSClient ws;

    // ...
}
//#field
