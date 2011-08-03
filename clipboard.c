#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <gtkmm.h>
#include <gtkmm/main.h>
#include <signal.h>

int main(int argc, char **argv) {
pid_t child;
if (!(child = fork())) {
Gtk::Main kit(argc, argv);

char * text = argv[1];

GtkClipboard * clipboard;

clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
gtk_clipboard_set_text(clipboard, text, strlen(text)+1);
gtk_clipboard_store(clipboard);

Gtk::Main::run();
} else {
usleep(1000*1000*5);
kill(child, SIGKILL);
}
return 0;
}
