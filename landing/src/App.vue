<template>
  <a
    class="skip"
    href="#contenido"
  >Saltar al contenido</a>

  <header class="topbar">
    <a
      class="brand"
      href="/"
    >
      <span
        class="brand__mark"
        aria-hidden="true"
      >🐕</span>
      <span class="brand__name">Sniff4Hound</span>
    </a>
    <nav
      class="topnav"
      aria-label="Principal"
    >
      <a href="#capacidades">Capacidades</a>
      <a href="#empezar">Empezar</a>
      <a href="/docs/">Documentacion</a>
      <a
        class="topnav__cta"
        :href="repo"
        rel="noopener"
      >GitHub</a>
    </nav>
  </header>

  <main id="contenido">
    <section class="hero">
      <p class="hero__eyebrow">
        Captura de telemetria y honeypot
      </p>
      <h1 class="hero__title">
        Ves tu red por dentro, sin dependencias que no controlas.
      </h1>
      <p class="hero__lead">
        Sniff4Hound captura con sockets crudos, decodifica los protocolos a mano y guarda todo en
        SQLite. El pipeline de captura no usa ni una libreria de terceros: solo
        <code>socket</code>, <code>threading</code> y <code>sqlite3</code>.
      </p>
      <div class="hero__actions">
        <a
          class="btn btn--primary"
          href="#empezar"
        >Instalar</a>
        <a
          class="btn"
          href="/docs/"
        >Leer la documentacion</a>
      </div>
      <dl class="stats">
        <div
          v-for="stat in stats"
          :key="stat.label"
          class="stat"
        >
          <dt>{{ stat.label }}</dt>
          <dd>{{ stat.value }}</dd>
        </div>
      </dl>
    </section>

    <section
      id="capacidades"
      class="section"
    >
      <h2>Que hace</h2>
      <div class="cards">
        <article
          v-for="item in features"
          :key="item.title"
          class="card"
        >
          <h3>{{ item.title }}</h3>
          <p>{{ item.body }}</p>
        </article>
      </div>
    </section>

    <section
      id="empezar"
      class="section"
    >
      <h2>Empezar</h2>
      <p class="section__lead">
        El artefacto oficial es un paquete Debian publicado en Releases. Tambien puedes instalarlo
        desde el codigo fuente.
      </p>
      <pre class="code"><code>{{ install }}</code></pre>
      <p class="note">
        La captura con sockets crudos necesita privilegios, pero el proceso web nunca corre como
        root: el privilegio vive solo en un hijo aislado que habla por IPC. Los detalles estan en
        <a href="/docs/architecture/">Arquitectura</a>.
      </p>
    </section>

    <section class="section">
      <h2>Licencia y propiedad</h2>
      <p class="section__lead">
        Codigo bajo licencia MIT. El nombre <strong>Sniff4Hound</strong>, los logotipos y el dominio
        oficial quedan reservados a su autor: la licencia MIT no concede derechos de marca. Lo
        detalla el <a
          :href="`${repo}/blob/main/NOTICE`"
          rel="noopener"
        >NOTICE</a>.
      </p>
    </section>
  </main>

  <footer class="footer">
    <p>
      Sniff4Hound — <a
        :href="repo"
        rel="noopener"
      >codigo fuente</a> ·
      <a
        :href="`${repo}/blob/main/LICENSE`"
        rel="noopener"
      >MIT</a> ·
      <a
        :href="`${repo}/security/policy`"
        rel="noopener"
      >Seguridad</a>
    </p>
    <p class="footer__meta">
      Hecho por JorgelSC Dev
    </p>
  </footer>
</template>

<script setup>
const repo = "https://github.com/jorgelsc-dev/Sniff4Hound";

const stats = [
  { label: "Protocolos identificados", value: "108" },
  { label: "Con decodificador propio", value: "26" },
  { label: "Dependencias de captura", value: "0" },
];

const features = [
  {
    title: "Captura cruda",
    body:
      "Un hilo por interfaz sobre sockets crudos. Ethernet, VLAN, IPv4/IPv6, ARP, TCP, UDP, ICMP y mas, parseados a mano con comprobacion de limites: un frame malformado nunca tumba la captura.",
  },
  {
    title: "Honeypot integrado",
    body:
      "Escuchas TCP y UDP que responden con banners realistas. Sniffer y honeypot son motores independientes: puedes ejecutar ninguno, uno o los dos a la vez.",
  },
  {
    title: "Protocolos de aplicacion",
    body:
      "HTTP, TLS, SSH, DNS, SMB, LDAP, Kerberos, BGP, QUIC, LLDP, CDP y mas. No solo se nombran: se extraen campos, y el modo 7 de NTP se marca como vector de amplificacion.",
  },
  {
    title: "Panel en vivo",
    body:
      "SPA en Vue 3 servida por el mismo proceso, con WebSocket para eventos. Vista por protocolo con estadisticas propias de cada uno, radar de hosts, mapa y triaje SOC.",
  },
  {
    title: "Deteccion",
    body:
      "Monitores declarativos sobre puertos, protocolos, banderas TCP, expresiones regulares de payload y listas negras, con severidades y deduplicacion de alertas.",
  },
  {
    title: "Exportacion",
    body:
      "Alertas, endpoints, flujos y dominios en CSV o JSON con forma de IOC, listos para un ticket o para un TIP.",
  },
];

const install = `# Paquete Debian (recomendado)
sudo apt install ./sniff4hound_*.deb
sniff4hound

# Desde el codigo fuente
git clone https://github.com/jorgelsc-dev/Sniff4Hound.git
cd Sniff4Hound
python -m pip install -e .
sniff4hound`;
</script>
