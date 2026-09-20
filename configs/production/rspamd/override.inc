logging {
  type = "console";
  level = "notice";
}

# The production boundary intentionally has one Rspamd worker and no Redis
# service. Keep Bayes durable on the existing Rspamd data volume instead of
# leaving the distribution default pointed at a nonexistent backend.
classifier "bayes" {
  backend = "sqlite3";
  cache {
    path = "/var/lib/rspamd/learn_cache.sqlite";
  }
  statfile {
    symbol = "BAYES_HAM";
    spam = false;
    path = "/var/lib/rspamd/bayes.ham.sqlite3";
  }
  statfile {
    symbol = "BAYES_SPAM";
    spam = true;
    path = "/var/lib/rspamd/bayes.spam.sqlite3";
  }
}

worker "normal" {
  bind_socket = "0.0.0.0:11333";
  count = 1;
}

worker "controller" {
  bind_socket = "0.0.0.0:11334";
  count = 1;
  password = "@GOTTH_MAIL_RSPAMD_CONTROLLER_TOKEN@";
  enable_password = "@GOTTH_MAIL_RSPAMD_CONTROLLER_TOKEN@";
}

worker "rspamd_proxy" {
  bind_socket = "0.0.0.0:11332";
  count = 1;
  milter = yes;
  timeout = 120s;
  upstream "local" {
    default = yes;
    self_scan = yes;
  }
}
