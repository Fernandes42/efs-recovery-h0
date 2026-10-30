// Minimal JSON value parser/printer for author-controlled files.
#include "grader/grader.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

namespace grader {
namespace {

struct P {
  const char* s;
  void ws() {
    while (*s && std::isspace((unsigned char)*s)) ++s;
  }
  Json val() {
    ws();
    if (*s == '{') return obj();
    if (*s == '[') return arr();
    if (*s == '"') {
      Json j;
      j.t = Json::T::STR;
      j.str = str();
      return j;
    }
    if (*s == 't') {
      expect("true");
      Json j;
      j.t = Json::T::NUM;
      j.num = 1;
      return j;
    }
    if (*s == 'f') {
      expect("false");
      Json j;
      j.t = Json::T::NUM;
      j.num = 0;
      return j;
    }
    if (*s == 'n') {
      expect("null");
      return Json{};
    }
    Json j;
    j.t = Json::T::NUM;
    char* e = nullptr;
    j.num = std::strtod(s, &e);
    if (e == s) throw std::runtime_error("bad json number");
    s = e;
    return j;
  }
  void expect(const char* w) {
    while (*w) {
      if (*s != *w) throw std::runtime_error("bad json literal");
      ++s;
      ++w;
    }
  }
  std::string str() {
    ++s;  // "
    std::string o;
    while (*s && *s != '"') {
      if (*s == '\\') {
        ++s;
        if (*s == 'n')
          o += '\n';
        else if (*s == 't')
          o += '\t';
        else
          o += *s;
        if (*s) ++s;
      } else {
        o += *s++;
      }
    }
    if (*s != '"') throw std::runtime_error("unterminated string");
    ++s;
    return o;
  }
  Json arr() {
    Json j;
    j.t = Json::T::ARR;
    ++s;
    ws();
    if (*s == ']') {
      ++s;
      return j;
    }
    while (true) {
      j.arr.push_back(val());
      ws();
      if (*s == ',') {
        ++s;
        continue;
      }
      if (*s == ']') {
        ++s;
        break;
      }
      throw std::runtime_error("bad json array");
    }
    return j;
  }
  Json obj() {
    Json j;
    j.t = Json::T::OBJ;
    ++s;
    ws();
    if (*s == '}') {
      ++s;
      return j;
    }
    while (true) {
      ws();
      if (*s != '"') throw std::runtime_error("bad json object key");
      std::string k = str();
      ws();
      if (*s != ':') throw std::runtime_error("bad json object colon");
      ++s;
      j.obj[k] = val();
      ws();
      if (*s == ',') {
        ++s;
        continue;
      }
      if (*s == '}') {
        ++s;
        break;
      }
      throw std::runtime_error("bad json object");
    }
    return j;
  }
};

void DumpInto(const Json& j, std::string& o) {
  switch (j.t) {
    case Json::T::NUL:
      o += "null";
      break;
    case Json::T::NUM: {
      char b[32];
      std::snprintf(b, sizeof b, "%.0f", j.num);
      o += b;
      break;
    }
    case Json::T::STR:
      o += '"';
      for (char ch : j.str) {
        if (ch == '"' || ch == '\\') o += '\\';
        o += ch;
      }
      o += '"';
      break;
    case Json::T::ARR:
      o += '[';
      for (size_t i = 0; i < j.arr.size(); ++i) {
        if (i) o += ',';
        DumpInto(j.arr[i], o);
      }
      o += ']';
      break;
    case Json::T::OBJ:
      o += '{';
      {
        bool first = true;
        for (auto& [k, v] : j.obj) {
          if (!first) o += ',';
          first = false;
          Json kk;
          kk.t = Json::T::STR;
          kk.str = k;
          DumpInto(kk, o);
          o += ':';
          DumpInto(v, o);
        }
      }
      o += '}';
      break;
  }
}

}  // namespace

Json Json::Parse(const std::string& s) {
  P p{s.c_str()};
  Json j = p.val();
  p.ws();
  if (*p.s) throw std::runtime_error("trailing json");
  return j;
}

std::string Json::Dump() const {
  std::string o;
  DumpInto(*this, o);
  return o;
}

std::vector<uint8_t> Pattern(size_t n, uint64_t seed) {
  std::vector<uint8_t> o(n);
  uint64_t x = 0x12345678u + seed * 0x9E3779B97F4A7C15ull;
  for (size_t i = 0; i < n; ++i) {
    x = x * 6364136223846793005ull + 1442695040888963407ull;
    o[i] = uint8_t((x >> 33) & 0xFF);
  }
  return o;
}

}  // namespace grader
