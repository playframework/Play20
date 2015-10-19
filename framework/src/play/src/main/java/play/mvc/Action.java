/*
 * Copyright (C) 2009-2015 Typesafe Inc. <http://www.typesafe.com>
 */
package play.mvc;

import play.mvc.Http.*;

import java.util.concurrent.CompletionStage;

/**
 * An action acts as decorator for the action method call.
 */
public abstract class Action<T> extends Results {
    
    /**
     * The action configuration - typically the annotation used to decorate the action method.
     */
    public T configuration;
    
    /**
     * The wrapped action.
     */
    public Action<?> delegate;
    
    /**
     * Executes this action with the given HTTP context and returns the result.
     */
    public abstract CompletionStage<Result> call(Context ctx);
    
    /**
     * A simple action with no configuration.
     */
    public static abstract class Simple extends Action<Void> {}
    
}
