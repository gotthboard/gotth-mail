logging {
  type = "console";
  level = "notice";
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
