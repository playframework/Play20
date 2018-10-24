/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */

package play.data;

import com.typesafe.config.Config;

import javax.validation.ValidatorFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import play.data.format.Formatters;
import play.data.validation.ValidationError;
import play.i18n.MessagesApi;
import play.mvc.Http;

/**
 * A dynamic form. This form is backed by a simple <code>HashMap&lt;String,String&gt;</code>
 */
public class DynamicForm extends Form<DynamicForm.Dynamic> {

    /** Statically compiled Pattern for checking if a key is already surrounded by "data[]". */
    private static final Pattern MATCHES_DATA = Pattern.compile("^data\\[.+\\]$");

    /**
     * Creates a new empty dynamic form.
     *
     * @param messagesApi    the messagesApi component.
     * @param formatters     the formatters component.
     * @param validatorFactory      the validatorFactory component.
     * @param config      the config component.
     */
    public DynamicForm(MessagesApi messagesApi, Formatters formatters, ValidatorFactory validatorFactory, Config config) {
        super(DynamicForm.Dynamic.class, messagesApi, formatters, validatorFactory, config);
    }

    /**
     * Creates a new dynamic form.
     *
     * @param data the current form data (used to display the form)
     * @param errors the collection of errors associated with this form
     * @param value optional concrete value if the form submission was successful
     * @param messagesApi    the messagesApi component.
     * @param formatters     the formatters component.
     * @param validatorFactory      the validatorFactory component.
     * @param config      the config component.
     */
    public DynamicForm(Map<String,String> data, List<ValidationError> errors, Optional<Dynamic> value, MessagesApi messagesApi, Formatters formatters, ValidatorFactory validatorFactory, Config config) {
        super(null, DynamicForm.Dynamic.class, data, errors, value, messagesApi, formatters, validatorFactory, config);
    }

    /**
     * Gets the concrete value only if the submission was a success.
     * If the form is invalid because of validation errors this method will return null.
     * If you want to retrieve the value even when the form is invalid use {@link #value(String)} instead.
     *
     * @param key the string key.
     * @return the value, or null if there is no match.
     */
    public String get(String key) {
        try {
            return (String)get().getData().get(asNormalKey(key));
        } catch(Exception e) {
            return null;
        }
    }

    /**
     * Gets the concrete value
     * @param key the string key.
     * @return the value
     */
    public Optional<Object> value(String key) {
        return super.value().map(v -> v.getData().get(asNormalKey(key)));
    }

    @Override
    public Map<String, String> rawData() {
        return Collections.unmodifiableMap(super.rawData().entrySet().stream().collect(Collectors.toMap(e -> asNormalKey(e.getKey()), e -> e.getValue())));
    }

    /**
     * Fills the form with existing data.
     * @param value    the map of values to fill in the form.
     * @return the modified form.
     */
    public DynamicForm fill(Map<String, Object> value) {
        Form<Dynamic> form = super.fill(new Dynamic(value));
        return new DynamicForm(form.rawData(), form.errors(), form.value(), messagesApi, formatters, validatorFactory, config);
    }

    @Override
    public DynamicForm bindFromRequest(String... allowedFields) {
        return bind(requestData(play.mvc.Controller.request()), allowedFields);
    }

    @Override
    public DynamicForm bindFromRequest(Http.Request request, String... allowedFields) {
        return bind(requestData(request), allowedFields);
    }

    @Override
    public DynamicForm bind(Map<String,String> data, String... allowedFields) {
        Form<Dynamic> form = super.bind(data.entrySet().stream().collect(Collectors.toMap(e -> asDynamicKey(e.getKey()), e -> e.getValue())), allowedFields);
        return new DynamicForm(form.rawData(), form.errors(), form.value(), messagesApi, formatters, validatorFactory, config);
    }

    @Override
    public Form.Field field(String key) {
        // #1310: We specify inner class as Form.Field rather than Field because otherwise,
        // javadoc cannot find the static inner class.
        Field field = super.field(asDynamicKey(key));
        return new Field(this, key, field.constraints(), field.format(), field.errors(),
            field.value().orElse((String)value(key).orElse(null))
        );
    }

    @Override
    @Deprecated
    public Optional<ValidationError> getError(String key) {
        return error(key);
    }

    @Override
    public Optional<ValidationError> error(String key) {
        return super.error(asDynamicKey(key));
    }

    @Override
    public DynamicForm withError(final String key, final String error, final List<Object> args) {
        final Form<Dynamic> form = super.withError(asDynamicKey(key), error, args);
        return new DynamicForm(super.rawData(), form.errors(), form.value(), this.messagesApi, this.formatters, this.validatorFactory, this.config);
    }

    @Override
    public DynamicForm withError(final String key, final String error) {
        return withError(key, error, new ArrayList<>());
    }

    // -- tools

    static String asDynamicKey(String key) {
        if(key.isEmpty() || MATCHES_DATA.matcher(key).matches()) {
           return key;
        } else {
            return "data[" + key + "]";
        }
    }

    static String asNormalKey(String key) {
        if(MATCHES_DATA.matcher(key).matches()) {
           return key.substring(5, key.length() - 1);
        } else {
            return key;
        }
    }

    // -- /

    /**
     * Simple data structure used by <code>DynamicForm</code>.
     */
    public static class Dynamic {

        private Map<String, Object> data = new HashMap<>();

        public Dynamic() {
        }

        public Dynamic(Map<String, Object> data) {
            this.data = data;
        }

        /**
         * @return the data.
         */
        public Map<String, Object> getData() {
            return data;
        }

        /**
         * Sets the new data.
         * @param data    the map of data.
         */
        public void setData(Map<String, Object> data) {
            this.data = data;
        }

        public String toString() {
            return "Form.Dynamic(" + data.toString() + ")";
        }

    }

}

