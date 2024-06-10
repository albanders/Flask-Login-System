This is a simple user/login system created using the Python Flask library.

It includes a login page for authentication and an admin page for creating/updating/deleting user accounts. User details are stored in a local SQLite3 database, with passwords being hashed through SHA-256. Routes can be made available only to logged in or admin users via added decorator functions.

User "admin" with password "123" is created on running the app.py script for the first time. This user can safely be deleted via the admin interface once proper accounts have been set up.

Feel free to use this as a template for small projects or for learning the basics of Flask, though I would not recommend it for use beyond these scopes.
