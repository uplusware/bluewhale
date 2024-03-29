/*
        Copyright (c) openheap, uplusware
        uplusware@gmail.com
*/

#include "session.h"

Session::Session(int epoll_fd,
                 int sockfd,
                 const char* clientip,
                 BOOL http_proxy) {
  m_epoll_fd = epoll_fd;
  m_client_bufs.clear();

  m_use_count = 0;
  m_client_sockfd = sockfd;
  m_clientip = clientip;

  m_backend_sockfd = -1;
  m_backend_sockfd_established = FALSE;
  m_http_proxy = http_proxy;
}

Session::~Session() {
  list<buf_desc*>::iterator itor;

  for (itor = m_client_bufs.begin(); itor != m_client_bufs.end(); ++itor) {
    delete *itor;
  }

  for (itor = m_backend_bufs.begin(); itor != m_backend_bufs.end(); ++itor) {
    delete *itor;
  }

  if (m_backend_sockfd > 0) {
    shutdown(m_backend_sockfd, SHUT_RDWR);
    m_backend_sockfd = -1;
  }

  if (m_client_sockfd > 0) {
    shutdown(m_client_sockfd, SHUT_RDWR);
    m_client_sockfd = -1;
  }
}

BOOL Session::connect_backend(const char* backhost_ip,
                              unsigned short backhost_port) {
  struct addrinfo hints;
  struct addrinfo *servinfo, *curr;
  struct sockaddr_in* sa;
  struct sockaddr_in6* sa6;

  int res;

  /* struct addrinfo hints; */
  struct addrinfo *server_addr, *rp;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
  hints.ai_flags = AI_PASSIVE;     /* For wildcard IP address */
  hints.ai_protocol = 0;           /* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  char szPort[32];
  sprintf(szPort, "%u", backhost_port);
  if (getaddrinfo((backhost_ip && backhost_ip[0] != '\0') ? backhost_ip : NULL,
                  szPort, &hints, &server_addr) != 0) {
    string strError = backhost_ip;
    strError += ":";
    strError += szPort;
    strError += " ";
    strError += strerror(errno);

    fprintf(stderr, "%s\n", strError.c_str());
    return FALSE;
  }

  BOOL connected = FALSE;
  for (rp = server_addr; rp != NULL; rp = rp->ai_next) {
    m_backend_sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (m_backend_sockfd == -1)
      continue;

    int flags = fcntl(m_backend_sockfd, F_GETFL, 0);
    fcntl(m_backend_sockfd, F_SETFL, flags | O_NONBLOCK);

    int s = connect(m_backend_sockfd, rp->ai_addr, rp->ai_addrlen);
    if (s == 0 || (s == -1 && errno == EINPROGRESS)) {
      connected = TRUE;
      break;
    }
  }

  freeaddrinfo(server_addr); /* No longer needed */

  if (!connected) {
    string strError = backhost_ip;
    strError += ":";
    strError += szPort;
    strError += " ";
    strError += strerror(errno);

    fprintf(stderr, "%s\n", strError.c_str());
    return FALSE;
  }

  return TRUE;
}

void Session::append_client_buf(const char* buf, int len) {
  if (len <= BUF_DESC_MAX_SIZE) {
    buf_desc* bd = new buf_desc;
    bd->cur = 0;
    bd->len = len;
    memcpy(bd->buf, buf, len);
    m_client_bufs.push_back(bd);
  } else {
    int have_pushed = 0;
    while (have_pushed < len) {
      if ((len - have_pushed) > BUF_DESC_MAX_SIZE) {
        buf_desc* bd = new buf_desc;
        bd->cur = 0;
        bd->len = BUF_DESC_MAX_SIZE;
        memcpy(bd->buf, buf + have_pushed, BUF_DESC_MAX_SIZE);
        m_client_bufs.push_back(bd);
        have_pushed += BUF_DESC_MAX_SIZE;
      } else {
        buf_desc* bd = new buf_desc;
        bd->cur = 0;
        bd->len = len - have_pushed;
        memcpy(bd->buf, buf, len - have_pushed);
        m_client_bufs.push_back(bd);
        have_pushed = len;
        break;
      }
    }
  }
}

void Session::append_backend_buf(const char* buf, int len) {
  if (len <= BUF_DESC_MAX_SIZE) {
    buf_desc* bd = new buf_desc;
    bd->cur = 0;
    bd->len = len;
    memcpy(bd->buf, buf, len);
    m_backend_bufs.push_back(bd);
  } else {
    int have_pushed = 0;
    while (have_pushed < len) {
      if ((len - have_pushed) > BUF_DESC_MAX_SIZE) {
        buf_desc* bd = new buf_desc;
        bd->cur = 0;
        bd->len = BUF_DESC_MAX_SIZE;
        memcpy(bd->buf, buf + have_pushed, BUF_DESC_MAX_SIZE);
        m_backend_bufs.push_back(bd);
        have_pushed += BUF_DESC_MAX_SIZE;
      } else {
        buf_desc* bd = new buf_desc;
        bd->cur = 0;
        bd->len = len - have_pushed;
        memcpy(bd->buf, buf, len - have_pushed);
        m_backend_bufs.push_back(bd);
        have_pushed = len;
        break;
      }
    }
  }
}
int Session::recv_from_client() {
  if (m_client_bufs.size() < 10) {
    if (m_client_bufs.size() > 0) {
      buf_desc* bd = m_client_bufs.back();
      do {
        if (bd->len <= BUF_DESC_REUSE_SIZE) {
          int r = recv(m_client_sockfd, bd->buf + bd->len,
                       BUF_DESC_MAX_SIZE - bd->len, 0);
          if (r > 0) {
            printf("%.*s", r, bd->buf + bd->len);
            bd->len += r;
            return bd->len;
          } else if (r == 0 || (r < 0 && errno != EAGAIN)) {
            shutdown(m_client_sockfd, SHUT_RDWR);
            m_client_sockfd = -1;
            shutdown(m_backend_sockfd, SHUT_WR);

            return -1;
          }
        }
      } while (0);
    }
    // continue
    buf_desc* bd = new buf_desc;
    do {
      bd->len = recv(m_client_sockfd, bd->buf, BUF_DESC_MAX_SIZE, 0);
      if (bd->len > 0) {
        bd->cur = 0;
        m_client_bufs.push_back(bd);
        send_to_backend();
        return bd->len;
      } else if (bd->len == 0 || (bd->len < 0 && errno != EAGAIN)) {
        delete bd;
        shutdown(m_client_sockfd, SHUT_RDWR);
        m_client_sockfd = -1;
        shutdown(m_backend_sockfd, SHUT_WR);
        return -1;
      }
    } while (0);
  } else
    send_to_backend();
  return 0;
}

int Session::recv_from_backend() {
  if (m_backend_bufs.size() < 10) {
    if (m_backend_bufs.size() > 0) {
      buf_desc* bd = m_backend_bufs.back();
      if (bd->len <= BUF_DESC_REUSE_SIZE) {
        do {
          int r = recv(m_backend_sockfd, bd->buf + bd->len,
                       BUF_DESC_MAX_SIZE - bd->len, 0);
          if (r > 0) {
            bd->len += r;
            return bd->len;
          } else if (r == 0 || (r < 0 && errno != EAGAIN)) {
            shutdown(m_backend_sockfd, SHUT_RDWR);
            m_backend_sockfd = -1;
            shutdown(m_client_sockfd, SHUT_WR);
            return -1;
          }
        } while (0);
      }
    }
    // continue
    buf_desc* bd = new buf_desc;
    do {
      bd->len = recv(m_backend_sockfd, bd->buf, BUF_DESC_MAX_SIZE, 0);
      if (bd->len > 0) {
        bd->cur = 0;
        m_backend_bufs.push_back(bd);
        send_to_client();
        return bd->len;
      } else if (bd->len == 0 || (bd->len < 0 && errno != EAGAIN)) {
        delete bd;

        shutdown(m_backend_sockfd, SHUT_RDWR);
        m_backend_sockfd = -1;
        shutdown(m_client_sockfd, SHUT_WR);

        return -1;
      }
    } while (0);
  } else
    send_to_client();
  return 0;
}

int Session::send_to_client() {
  if (m_backend_bufs.size() > 0) {
    buf_desc* bd = m_backend_bufs.front();
    do {
      int s = send(m_client_sockfd, bd->buf + bd->cur, bd->len - bd->cur, 0);
      if (s > 0) {
        bd->cur += s;
        if (bd->cur == bd->len) {
          delete bd;
          m_backend_bufs.pop_front();
        }

        if (m_backend_bufs.size() > 0) {
          struct epoll_event ev;
          ev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;
          ev.data.fd = m_client_sockfd;
          epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, m_client_sockfd, &ev);
        } else  // .size() == 0
        {
          struct epoll_event ev;
          ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
          ev.data.fd = m_client_sockfd;
          epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, m_client_sockfd, &ev);
        }
        return s;
      } else if (s == 0 || (s < 0 && errno != EAGAIN)) {
        shutdown(m_backend_sockfd, SHUT_RD);
        shutdown(m_client_sockfd, SHUT_RDWR);
        m_client_sockfd = -1;
        return -1;
      }
    } while (0);
  } else {
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    ev.data.fd = m_client_sockfd;
    epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, m_client_sockfd, &ev);

    if (m_backend_sockfd ==
        -1)  // client is close and no data to send for backend.
    {
      shutdown(m_client_sockfd, SHUT_WR);
      return -1;
    }
  }

  return 0;
}

int Session::send_to_backend() {
  if (!m_backend_sockfd_established) {
    return 0;
  }

  if (m_client_bufs.size() > 0) {
    buf_desc* bd = m_client_bufs.front();
    do {
      int s = send(m_backend_sockfd, bd->buf + bd->cur, bd->len - bd->cur, 0);
      if (s > 0) {
        bd->cur += s;
        if (bd->cur == bd->len) {
          delete bd;
          m_client_bufs.pop_front();
        }

        if (m_client_bufs.size() > 0) {
          struct epoll_event ev;
          ev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR;
          ev.data.fd = m_backend_sockfd;
          epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, m_backend_sockfd, &ev);
        } else  // .size() == 0
        {
          struct epoll_event ev;
          ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
          ev.data.fd = m_backend_sockfd;
          epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, m_backend_sockfd, &ev);
        }

        return s;
      } else if (s == 0 || (s < 0 && errno != EAGAIN)) {
        shutdown(m_client_sockfd, SHUT_RD);
        shutdown(m_backend_sockfd, SHUT_RDWR);
        m_backend_sockfd = -1;
        return -1;
      }
    } while (0);
  } else {
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    ev.data.fd = m_backend_sockfd;
    epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, m_backend_sockfd, &ev);

    if (m_client_sockfd ==
        -1)  // client is close and no data to send for backend.
    {
      shutdown(m_backend_sockfd, SHUT_WR);
      return -1;
    }
  }
  return 0;
}