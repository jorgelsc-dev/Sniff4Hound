import { readFileSync } from "node:fs";
import { babelParse, parse } from "@vue/compiler-sfc";

// Evaluate the complete production Options API definition, with only the store
// and child SFCs substituted. Methods, computed state and lifecycle stay real.
export async function optionsView(name, store, dir = "views") {
  const url = new URL(`../../src/${dir}/${name}.vue`, import.meta.url);
  let code = parse(readFileSync(url, "utf8")).descriptor.script.content;
  const ast = babelParse(code, { sourceType: "module" });
  const bindings = {};
  for (const entry of [...ast.program.body].reverse()) {
    if (entry.type === "ImportDeclaration") {
      const source = entry.source.value;
      let module;
      if (source.endsWith(".vue")) module = { default: {} };
      else if (source.endsWith("/appStore")) module = { default: store };
      else module = await import(new URL(source.endsWith(".js") ? source : `${source}.js`, url));
      for (const spec of entry.specifiers) {
        bindings[spec.local.name] = spec.type === "ImportDefaultSpecifier" ? module.default : module[spec.imported.name];
      }
      code = code.slice(0, entry.start) + code.slice(entry.end);
    } else if (entry.type === "ExportDefaultDeclaration") {
      code = code.slice(0, entry.start) + "return " + code.slice(entry.declaration.start);
    }
  }
  const definition = new Function(...Object.keys(bindings), code)(...Object.values(bindings));
  const vm = definition.data();
  vm.$route = { params: { proto: "tcp" } };
  for (const [key, method] of Object.entries(definition.methods)) vm[key] = method.bind(vm);
  for (const [key, getter] of Object.entries(definition.computed)) {
    Object.defineProperty(vm, key, { get: getter.bind(vm) });
  }
  return { vm, definition };
}

export function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

export function feedStore() {
  const feeds = [];
  const reads = [];
  const store = {
    state: { apiBase: "fixture", timeRange: "1h" },
    openDataFeed(feed, params, message, unavailable) {
      const handle = { feed, params, message, unavailable, closed: false, close() { this.closed = true; } };
      feeds.push(handle);
      return handle;
    },
    extractArray: value => value,
    feedListResult: payload => ({ rows: payload.data }),
    fetchProtocolSnapshot(params) {
      const pending = deferred();
      reads.push({ ...pending, params });
      return pending.promise;
    },
    listDomains() { return this.fetchProtocolSnapshot(); },
    listPaths() { return this.fetchProtocolSnapshot(); },
  };
  return { store, feeds, reads };
}
