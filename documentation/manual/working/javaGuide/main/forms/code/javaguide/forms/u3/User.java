/*
 * Copyright (C) 2009-2017 Lightbend Inc. <https://www.lightbend.com>
 */
package javaguide.forms.u3;

import static javaguide.forms.JavaForms.authenticate;

//#user
import play.data.validation.Constraints;
import play.data.validation.Constraints.SelfValidatingSimple;
import play.data.validation.Constraints.ValidatableSimple;

@SelfValidatingSimple
public class User implements ValidatableSimple {

    @Constraints.Required
    protected String email;
    protected String password;

    @Override
    public String validateInstance() {
        if (authenticate(email, password) == null) {
            // You could also return a key defined in conf/messages
            return "Invalid email or password";
        }
        return null;
    }

    // getters and setters

    //###skip: 16
    public void setEmail(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

}
//#user
