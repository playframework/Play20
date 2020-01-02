/*
 * Copyright (C) Lightbend Inc. <https://www.lightbend.com>
 */

package javaguide.forms.customconstraint.nopayload;

// #constraint
import javax.inject.Inject;
import javax.validation.ConstraintValidatorContext;

import play.data.validation.Constraints.PlayConstraintValidator;

import play.db.Database;

public class ValidateWithDBValidator
    implements PlayConstraintValidator<ValidateWithDB, ValidatableWithDB<?>> {

  private final Database db;

  @Inject
  public ValidateWithDBValidator(final Database db) {
    this.db = db;
  }

  @Override
  public void initialize(final ValidateWithDB constraintAnnotation) {}

  @Override
  public boolean isValid(
      final ValidatableWithDB<?> value,
      final ConstraintValidatorContext constraintValidatorContext) {
    return reportValidationStatus(value.validate(this.db), constraintValidatorContext);
  }
}
// #constraint
