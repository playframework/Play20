/*
 * Copyright (C) 2009-2018 Lightbend Inc. <https://www.lightbend.com>
 */

package javaguide.i18n;

import org.junit.Test;

import static java.util.stream.Collectors.joining;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import javaguide.testhelpers.MockJavaAction;
import javaguide.testhelpers.MockJavaActionHelper;
import javaguide.i18n.html.indextemplate;
import javaguide.i18n.html.hellotemplate;
import javaguide.i18n.html.helloscalatemplate;
import play.Application;
import play.core.j.JavaHandlerComponents;
import play.mvc.Http;
import play.mvc.Result;
import play.test.WithApplication;
import static play.test.Helpers.*;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import play.i18n.Lang;
import play.i18n.Messages;
import play.i18n.MessagesApi;

import java.util.*;

public class JavaI18N extends WithApplication {

    @Override
    public Application provideApplication() {
        return fakeApplication(ImmutableMap.of(
            "play.i18n.langs", ImmutableList.of("en", "en-US", "fr"),
            "messages.path", "javaguide/i18n"
            ));
    }

    @Test
    public void checkSpecifyLangHello() {
        MessagesApi messagesApi = instanceOf(MessagesApi.class);
        //#specify-lang-render
        String title = messagesApi.get(Lang.forCode("fr"), "hello");
        //#specify-lang-render

        assertTrue(title.equals("bonjour"));
    }

    @Test
    public void checkDefaultHello() {
        Result result = MockJavaActionHelper.call(new DefaultLangController(instanceOf(JavaHandlerComponents.class)), fakeRequest("GET", "/"), mat);
        assertThat(contentAsString(result), containsString("hello"));
    }

    public static class DefaultLangController extends MockJavaAction {

        DefaultLangController(JavaHandlerComponents javaHandlerComponents) {
            super(javaHandlerComponents);
        }

        //#default-lang-render
        public Result index() {
            return ok(indextemplate.render()); // "hello"
        }
        //#default-lang-render
    }

    @Test
    public void checkDefaultScalaHello() {
        Result result = MockJavaActionHelper.call(new DefaultScalaLangController(instanceOf(JavaHandlerComponents.class)), fakeRequest("GET", "/"), mat);
        assertThat(contentAsString(result), containsString("hello"));
    }

    public static class DefaultScalaLangController extends MockJavaAction {

        DefaultScalaLangController(JavaHandlerComponents javaHandlerComponents) {
            super(javaHandlerComponents);
        }

        public Result index() {
            return ok(helloscalatemplate.render()); // "hello"
        }
    }

    @Test
    public void checkChangeLangHello() {
        Result result = MockJavaActionHelper.call(new ChangeLangController(instanceOf(JavaHandlerComponents.class), instanceOf(MessagesApi.class)), fakeRequest("GET", "/"), mat);
        assertThat(contentAsString(result), containsString("bonjour"));
    }

    @Test
    public void checkContextMessages() {
        ContextMessagesController c = app.injector().instanceOf(ContextMessagesController.class);
        Result result = MockJavaActionHelper.call(c, fakeRequest("GET", "/"), mat);
        assertThat(contentAsString(result), containsString("hello"));
    }

    public static class ChangeLangController extends MockJavaAction {

        private final MessagesApi messagesApi;

        ChangeLangController(JavaHandlerComponents javaHandlerComponents, MessagesApi messagesApi) {
            super(javaHandlerComponents);
            this.messagesApi = messagesApi;
        }

        //#change-lang-render
        public Result index() {
            Lang lang = Lang.forCode("fr");
            return ok(hellotemplate.render(lang)).withLang(lang, messagesApi); // "bonjour"
        }
        //#change-lang-render
    }

    public static class ContextMessagesController extends MockJavaAction {

        @javax.inject.Inject
        public ContextMessagesController(JavaHandlerComponents javaHandlerComponents) {
            super(javaHandlerComponents);
        }

        //#show-context-messages
        public Result index() {
            Messages messages = Http.Context.current().messages();
            String hello = messages.at("hello");
            return ok(indextemplate.render());
        }
        //#show-context-messages
    }

    @Test
    public void checkSetTransientLangHello() {
        Result result = MockJavaActionHelper.call(new SetTransientLangController(instanceOf(JavaHandlerComponents.class)), fakeRequest("GET", "/"), mat);
        assertThat(contentAsString(result), containsString("howdy"));
    }

    public static class SetTransientLangController extends MockJavaAction {

        SetTransientLangController(JavaHandlerComponents javaHandlerComponents) {
            super(javaHandlerComponents);
        }

        //#set-transient-lang-render
        public Result index() {
            ctx().setTransientLang("en-US");
            return ok(indextemplate.render()); // "howdy"
        }
        //#set-transient-lang-render
    }

    @Test
    public void testAcceptedLanguages() {
        Result result = MockJavaActionHelper.call(new AcceptedLanguageController(instanceOf(JavaHandlerComponents.class)), fakeRequest("GET", "/").header("Accept-Language", "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5"), mat);
        assertThat(contentAsString(result), equalTo("fr-CH,fr,en,de"));
    }

    private static final class AcceptedLanguageController extends MockJavaAction {
        AcceptedLanguageController(JavaHandlerComponents javaHandlerComponents) {
            super(javaHandlerComponents);
        }

        // #accepted-languages
        public Result index() {
            List<Lang> langs = request().acceptLanguages();
            String codes = langs.stream().map(Lang::code).collect(joining(","));
            return ok(codes);
        }
        // #accepted-languages
    }

    @Test
    public void testSingleApostrophe() {
        assertTrue(singleApostrophe());
    }

    private Boolean singleApostrophe() {
        MessagesApi messagesApi = app.injector().instanceOf(MessagesApi.class);
        Collection<Lang> candidates = Collections.singletonList(new Lang(Locale.US));
        Messages messages = messagesApi.preferred(candidates);
        //#single-apostrophe
        String errorMessage = messages.at("info.error");
        Boolean areEqual = errorMessage.equals("You aren't logged in!");
        //#single-apostrophe

        return areEqual;
    }

    @Test
    public void testEscapedParameters() {
        assertTrue(escapedParameters());
    }

    private Boolean escapedParameters() {
        MessagesApi messagesApi = app.injector().instanceOf(MessagesApi.class);
        Collection<Lang> candidates = Collections.singletonList(new Lang(Locale.US));
        Messages messages = messagesApi.preferred(candidates);
        //#parameter-escaping
        String errorMessage = messages.at("example.formatting");
        Boolean areEqual = errorMessage.equals("When using MessageFormat, '{0}' is replaced with the first parameter.");
        //#parameter-escaping

        return areEqual;
    }

    // #explicit-messages-api
    private MessagesApi explicitMessagesApi() {
        return new play.i18n.MessagesApi(
                new play.api.i18n.DefaultMessagesApi(
                        Collections.singletonMap(Lang.defaultLang().code(), Collections.singletonMap("foo", "bar")),
                        new play.api.i18n.DefaultLangs().asJava())
        );
    }
    // #explicit-messages-api

    @Test
    public void testExplicitMessagesApi() {
        MessagesApi messagesApi = explicitMessagesApi();
        String message = messagesApi.get(Lang.defaultLang(), "foo");
        assertThat(message, equalTo("bar"));
    }

}
