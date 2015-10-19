package javaguide.sql;

import javax.inject.Inject;

import play.mvc.Controller;
import play.db.NamedDatabase;
import play.db.Database;

// inject "orders" database instead of "default"
class JavaNamedDatabase extends Controller {
    @Inject @NamedDatabase("orders") Database db;
    // do whatever you need with the db
}
