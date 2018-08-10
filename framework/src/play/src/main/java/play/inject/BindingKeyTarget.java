/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */
package play.inject;

/**
 * A binding target that is provided by another key - essentially an alias.
 */
public final class BindingKeyTarget<T> extends BindingTarget<T> {
    private final play.api.inject.BindingKeyTarget<T> underlying;

    public BindingKeyTarget(final BindingKey<? extends T> key) {
        this(new play.api.inject.BindingKeyTarget<>(key.asScala()));
    }

    public BindingKeyTarget(final play.api.inject.BindingKeyTarget<T> underlying) {
        super();
        this.underlying = underlying;
    }

    public BindingKey<? extends T> getKey() {
        return underlying.key().asJava();
    }

    @Override
    public play.api.inject.BindingKeyTarget<T> asScala() {
        return underlying;
    }
}
