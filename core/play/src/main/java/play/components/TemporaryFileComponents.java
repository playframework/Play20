/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package play.components;

import play.libs.Files;

/** Components related to temporary file handle. */
public interface TemporaryFileComponents {

  Files.TemporaryFileCreator tempFileCreator();
}
