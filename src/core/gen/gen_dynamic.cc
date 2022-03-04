#include "core/gen/gen_dynamic.h"

#include <string>
#include <vector>

#include "base/config.h"

std::string FilteringStatement(const struct config& cfg) {
  const struct filter filter = cfg.if_filter;
  std::vector<std::string> filter_elements;

  // If config has filtering attributes, convert them into string.
  // ip_ver
  if (filter.ip_ver.has_value()) {
    filter_elements.push_back("iph->version==" +
                              std::to_string(filter.ip_ver.value()));
  }

  // ip_hlen
  if (filter.ip_hl.has_value()) {
    filter_elements.push_back("iph->ihl==" +
                              std::to_string(filter.ip_hl.value()));
  }

  // ip_tos
  if (filter.ip_tos.has_value()) {
    filter_elements.push_back("iph->tos==" +
                              std::to_string(filter.ip_tos.value()));
  }

  // ip_dscp
  if (filter.ip_dscp.has_value()) {
    filter_elements.push_back("(iph->tos&0xfc)==" +
                              std::to_string(filter.ip_dscp.value()));
  }

  // ip_ecn
  if (filter.ip_ecn.has_value()) {
    filter_elements.push_back("(iph->tos&0x03)==" +
                              std::to_string(filter.ip_ecn.value()));
  }

  // ip_tot_len
  if (filter.ip_tot_len.has_value()) {
    filter_elements.push_back("bpf_ntohs(iph->tot_len)==" +
                              std::to_string(filter.ip_tot_len.value()));
  }

  // ip_id
  if (filter.ip_id.has_value()) {
    filter_elements.push_back("bpf_ntohs(iph->id)==" +
                              std::to_string(filter.ip_id.value()));
  }

  // ip_flag_res
  if (filter.ip_flag_res.has_value()) {
    if (filter.ip_flag_res.value()) {
      filter_elements.push_back("iph->frag_off & 0x8000");
    } else {
      filter_elements.push_back("!(iph->frag_off & 0x8000)");
    }
  }

  // ip_flag_df
  if (filter.ip_flag_df.has_value()) {
    if (filter.ip_flag_df.value()) {
      filter_elements.push_back("iph->frag_off & 0x4000");
    } else {
      filter_elements.push_back("!(iph->frag_off & 0x4000)");
    }
  }

  // ip_flag_mf
  if (filter.ip_flag_mf.has_value()) {
    if (filter.ip_flag_mf.value()) {
      filter_elements.push_back("iph->frag_off & 0x2000");
    } else {
      filter_elements.push_back("!(iph->frag_off & 0x2000)");
    }
  }

  // ip_offset
  if (filter.ip_offset.has_value()) {
    filter_elements.push_back("(iph->frag_off & 0x00ff)==" +
                              std::to_string(filter.ip_offset.value()));
  }

  // ip_ttl
  if (filter.ip_ttl.has_value()) {
    filter_elements.push_back("iph->ttl==" +
                              std::to_string(filter.ip_ttl.value()));
  }

  // ip_protocol
  if (filter.ip_protocol.has_value()) {
    filter_elements.push_back("iph->protocol==" +
                              std::to_string(filter.ip_protocol.value()));
  }

  // ip_check
  if (filter.ip_check.has_value()) {
    filter_elements.push_back("iph->check==bpf_htons(" +
                              std::to_string(filter.ip_check.value()) + ")");
  }

  // tcp_src
  if (filter.tcp_src.has_value()) {
    filter_elements.push_back("tcph->source==bpf_htons(" +
                              std::to_string(filter.tcp_src.value()) + ")");
  }

  // tcp_dest
  if (filter.tcp_dest.has_value()) {
    filter_elements.push_back("tcph->dest==bpf_htons(" +
                              std::to_string(filter.tcp_dest.value()) + ")");
  }

  // tcp_seq
  if (filter.tcp_seq.has_value()) {
    filter_elements.push_back("tcph->seq==bpf_htons(" +
                              std::to_string(filter.tcp_seq.value()) + ")");
  }

  // tcp_ack_seq
  if (filter.tcp_ack_seq.has_value()) {
    filter_elements.push_back("tcph->ack_seq==bpf_htons(" +
                              std::to_string(filter.tcp_ack_seq.value()) + ")");
  }

  // tcp_hlen
  if (filter.tcp_hlen.has_value()) {
    filter_elements.push_back("tcph->doff==" +
                              std::to_string(filter.tcp_hlen.value()));
  }

  // tcp_res
  if (filter.tcp_res.has_value()) {
    filter_elements.push_back("tcph->res1==" +
                              std::to_string(filter.tcp_res.value()));
  }

  // tcp_cwr
  if (filter.tcp_cwr.has_value()) {
    if (filter.tcp_cwr.value()) {
      filter_elements.push_back("tcph->cwr");
    } else {
      filter_elements.push_back("!tcph->cwr");
    }
  }

  // tcp_ece
  if (filter.tcp_ece.has_value()) {
    if (filter.tcp_ece.value()) {
      filter_elements.push_back("tcph->ece");
    } else {
      filter_elements.push_back("!tcph->ece");
    }
  }

  // tcp_urg
  if (filter.tcp_urg.has_value()) {
    if (filter.tcp_urg.value()) {
      filter_elements.push_back("tcph->urg");
    } else {
      filter_elements.push_back("!tcph->urg");
    }
  }

  // tcp_ack
  if (filter.tcp_ack.has_value()) {
    if (filter.tcp_ack.value()) {
      filter_elements.push_back("tcph->ack");
    } else {
      filter_elements.push_back("!tcph->ack");
    }
  }

  // tcp_psh
  if (filter.tcp_psh.has_value()) {
    if (filter.tcp_psh.value()) {
      filter_elements.push_back("tcph->psh");
    } else {
      filter_elements.push_back("!tcph->psh");
    }
  }

  // tcp_rst
  if (filter.tcp_rst.has_value()) {
    if (filter.tcp_rst.value()) {
      filter_elements.push_back("tcph->rst");
    } else {
      filter_elements.push_back("!tcph->rst");
    }
  }

  // tcp_syn
  if (filter.tcp_syn.has_value()) {
    if (filter.tcp_syn.value()) {
      filter_elements.push_back("tcph->syn");
    } else {
      filter_elements.push_back("!tcph->syn");
    }
  }

  // tcp_fin
  if (filter.tcp_fin.has_value()) {
    if (filter.tcp_fin.value()) {
      filter_elements.push_back("tcph->fin");
    } else {
      filter_elements.push_back("!tcph->fin");
    }
  }

  // tcp_window
  if (filter.tcp_window.has_value()) {
    filter_elements.push_back("tcph->window==bpf_htons(" +
                              std::to_string(filter.tcp_window.value()) + ")");
  }

  // tcp_check
  if (filter.tcp_check.has_value()) {
    filter_elements.push_back("tcph->check==bpf_htons(" +
                              std::to_string(filter.tcp_check.value()) + ")");
  }

  // tcp_urg_ptr
  if (filter.tcp_urg_ptr.has_value()) {
    filter_elements.push_back("tcph->urg_ptr==bpf_htons(" +
                              std::to_string(filter.tcp_urg_ptr.value()) + ")");
  }

  // udp_src
  if (filter.udp_src.has_value()) {
    filter_elements.push_back("udph->source==bpf_htons(" +
                              std::to_string(filter.udp_src.value()) + ")");
  }

  // udp_dest
  if (filter.udp_dest.has_value()) {
    filter_elements.push_back("udph->dest==bpf_htons(" +
                              std::to_string(filter.udp_dest.value()) + ")");
  }

  // udp_len
  if (filter.udp_len.has_value()) {
    filter_elements.push_back("udph->len==bpf_htons(" +
                              std::to_string(filter.udp_len.value()) + ")");
  }

  // udp_check
  if (filter.udp_check.has_value()) {
    filter_elements.push_back("udph->check==bpf_htons(" +
                              std::to_string(filter.udp_check.value()) + ")");
  }

  // icmp_type
  if (filter.icmp_type.has_value()) {
    filter_elements.push_back("icmph->type==bpf_htons(" +
                              std::to_string(filter.icmp_type.value()) + ")");
  }

  // icmp_code
  if (filter.icmp_code.has_value()) {
    filter_elements.push_back("icmph->code==bpf_htons(" +
                              std::to_string(filter.icmp_code.value()) + ")");
  }

  // icmp_check
  if (filter.icmp_check.has_value()) {
    filter_elements.push_back("icmph->checksum==bpf_htons(" +
                              std::to_string(filter.icmp_check.value()) + ")");
  }

  std::string s;
  if (cfg.use_udp) {
    s += "udph&&";
  } else if (cfg.use_tcp) {
    s += "tcph&&";
  } else if (cfg.use_icmp) {
    s += "icmph&&";
  }

  for (const auto& elements : filter_elements) {
    s += elements;
    s += "&&";
  }
  s = s.substr(0, s.length() - 2);

  std::string ret = "if(" + s + ")";
  return ret;
}

std::string RewriteStatement(const struct config& cfg) {
  std::string s = "{";
  const struct filter filter = cfg.then_filter;

  // ip_ver
  if (filter.ip_ver.has_value()) {
    s += "iph->version=";
    s += std::to_string(filter.ip_ver.value());
    s += ";";
  }

  // ip_hlen
  if (filter.ip_hl.has_value()) {
    s += "iph->ihl=";
    s += std::to_string(filter.ip_hl.value());
    s += ";";
  }

  // ip_tos
  if (filter.ip_tos.has_value()) {
    s += "iph->tos=";
    s += std::to_string(filter.ip_tos.value());
    s += ";";
  }

  // ip_dscp
  if (filter.ip_dscp.has_value()) {
    s += "iph->tos|=";
    s += std::to_string(filter.ip_dscp.value());
    s += ";";
  }

  // ip_ecn
  if (filter.ip_ecn.has_value()) {
    s += "iph->tos|=";
    s += std::to_string(filter.ip_ecn.value());
    s += ";";
  }

  // ip_tot_len
  if (filter.ip_tot_len.has_value()) {
    s += "iph->tot_len=bpf_htons(";
    s += std::to_string(filter.ip_tot_len.value());
    s += ");";
  }

  // ip_id
  if (filter.ip_id.has_value()) {
    s += "iph->id=bpf_htons(";
    s += std::to_string(filter.ip_id.value());
    s += ");";
  }

  // ip_flag_res
  if (filter.ip_flag_res.has_value()) {
    if (filter.ip_flag_res.value()) {
      s += "iph->frag_off |= bpf_htons(0x8000);";
    } else {
      s += "iph->frag_off &= bpf_htons(0x7fff);";
    }
  }

  // ip_flag_df
  if (filter.ip_flag_df.has_value()) {
    if (filter.ip_flag_df.value()) {
      s += "iph->frag_off |= bpf_htons(0x4000);";
    } else {
      s += "iph->frag_off &= bpf_htons(0xbfff);";
    }
  }

  // ip_flag_mf
  if (filter.ip_flag_mf.has_value()) {
    if (filter.ip_flag_mf.value()) {
      s += "iph->frag_off |= bpf_htons(0x2000);";
    } else {
      s += "iph->frag_off &= bpf_htons(0xdfff);";
    }
  }

  // ip_offset
  if (filter.ip_offset.has_value()) {
    s += "iph->frag_off |= bpf_htons(";
    s += std::to_string(filter.ip_offset.value());
    s += ");";
  }

  // ip_ttl
  if (filter.ip_ttl.has_value()) {
    s += "iph->ttl=";
    s += std::to_string(filter.ip_ttl.value());
    s += ";";
  }

  // ip_protocol
  if (filter.ip_protocol.has_value()) {
    s += "iph->protocol=";
    s += std::to_string(filter.ip_protocol.value());
    s += ";";
  }

  // ip_check
  if (filter.ip_check.has_value()) {
    s += "iph->check=bpf_htons(";
    s += std::to_string(filter.ip_check.value());
    s += ");";
  }

  // tcp_src
  if (filter.tcp_src.has_value()) {
    s += "tcph->source=bpf_htons(";
    s += std::to_string(filter.tcp_src.value());
    s += ");";
  }

  // tcp_dest
  if (filter.tcp_dest.has_value()) {
    s += "tcph->dest=bpf_htons(";
    s += std::to_string(filter.tcp_dest.value());
    s += ");";
  }

  // tcp_seq
  if (filter.tcp_seq.has_value()) {
    s += "tcph->seq=bpf_htons(";
    s += std::to_string(filter.tcp_seq.value());
    s += ");";
  }

  // tcp_ack_seq
  if (filter.tcp_ack_seq.has_value()) {
    s += "tcph->ack_seq=bpf_htons(";
    s += std::to_string(filter.tcp_ack_seq.value());
    s += ");";
  }

  // tcp_hlen
  if (filter.tcp_hlen.has_value()) {
    s += "tcph->doff=";
    s += std::to_string(filter.tcp_hlen.value());
    s += ";";
  }

  // tcp_res
  if (filter.tcp_res.has_value()) {
    s += "tcph->res1=";
    s += std::to_string(filter.tcp_res.value());
    s += ";";
  }

  // tcp_cwr
  if (filter.tcp_cwr.has_value()) {
    if (filter.tcp_cwr.value()) {
      s += "tcph->cwr=1;";
    } else {
      s += "tcph->cwr=0;";
    }
  }

  // tcp_urg
  if (filter.tcp_urg.has_value()) {
    if (filter.tcp_urg.value()) {
      s += "tcph->urg=1;";
    } else {
      s += "tcph->urg=0;";
    }
  }

  // tcp_ack
  if (filter.tcp_ack.has_value()) {
    if (filter.tcp_ack.value()) {
      s += "tcph->ack=1;";
    } else {
      s += "tcph->ack=0;";
    }
  }

  // tcp_psh
  if (filter.tcp_psh.has_value()) {
    if (filter.tcp_psh.value()) {
      s += "tcph->psh=1;";
    } else {
      s += "tcph->psh=0;";
    }
  }

  // tcp_rst
  if (filter.tcp_rst.has_value()) {
    if (filter.tcp_rst.value()) {
      s += "tcph->rst=1;";
    } else {
      s += "tcph->rst=0;";
    }
  }

  // tcp_syn
  if (filter.tcp_syn.has_value()) {
    if (filter.tcp_syn.value()) {
      s += "tcph->syn=1;";
    } else {
      s += "tcph->syn=0;";
    }
  }

  // tcp_fin
  if (filter.tcp_fin.has_value()) {
    if (filter.tcp_fin.value()) {
      s += "tcph->fin=1;";
    } else {
      s += "tcph->fin=0;";
    }
  }

  // tcp_window
  if (filter.tcp_window.has_value()) {
    s += "tcph->window=bpf_htons(";
    s += std::to_string(filter.tcp_window.value());
    s += ");";
  }

  // tcp_check
  if (filter.tcp_check.has_value()) {
    s += "tcph->check=bpf_htons(";
    s += std::to_string(filter.tcp_check.value());
    s += ");";
  }

  // tcp_urg_ptr
  if (filter.tcp_urg_ptr.has_value()) {
    s += "tcph->urg_ptr=bpf_htons(";
    s += std::to_string(filter.tcp_urg_ptr.value());
    s += ");";
  }

  // udp_dest
  if (filter.udp_dest.has_value()) {
    s += "udph->dest=bpf_htons(";
    s += std::to_string(filter.udp_dest.value());
    s += ");";
  }

  // udp_len
  if (filter.udp_len.has_value()) {
    s += "udph->len=bpf_htons(";
    s += std::to_string(filter.udp_len.value());
    s += ");";
  }

  // udp_check
  if (filter.udp_check.has_value()) {
    s += "udph->check=bpf_htons(";
    s += std::to_string(filter.udp_check.value());
    s += ");";
  }

  s += "}else {return XDP_PASS;}\n";
  return s;
}
