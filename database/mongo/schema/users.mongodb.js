use("UNIDB");

db.createCollection("USERS");

db.getCollection("USERS").createIndex({ googleId: 1 }, { unique: true });

db.getCollection("USERS").createIndex({ email: 1 }, { unique: true });

db.getCollection("USERS").createIndex(
  { "phone.code": 1, "phone.number": 1 },
  { unique: true }
);
