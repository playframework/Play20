/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package play.data.validation;

import javax.inject.Inject;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorFactory;

import play.inject.Injector;

/** Creates validator instances with injections available. */
public class DefaultConstraintValidatorFactory implements ConstraintValidatorFactory {

  private Injector injector;

  @Inject
  public DefaultConstraintValidatorFactory(Injector injector) {
    this.injector = injector;
  }

  @Override
  public <T extends ConstraintValidator<?, ?>> T getInstance(final Class<T> key) {
    return this.injector.instanceOf(key);
  }

  @Override
  public void releaseInstance(final ConstraintValidator<?, ?> instance) {
    // Garbage collector will do it
  }
}
