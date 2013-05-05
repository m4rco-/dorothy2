--
-- PostgreSQL database dump
--

DROP DATABASE dorothive;


SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;

--
-- Name: dorothive; Type: DATABASE; Schema: -; Owner: postgres
--

CREATE DATABASE dorothive WITH TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'C' LC_CTYPE = 'C';


ALTER DATABASE dorothive OWNER TO postgres;

\connect dorothive

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;

--
-- Name: dorothy; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA dorothy;


ALTER SCHEMA dorothy OWNER TO postgres;

--
-- Name: SCHEMA dorothy; Type: COMMENT; Schema: -; Owner: postgres
--

COMMENT ON SCHEMA dorothy IS 'standard public schema';


--
-- Name: plpgsql; Type: PROCEDURAL LANGUAGE; Schema: -; Owner: postgres
--

CREATE OR REPLACE PROCEDURAL LANGUAGE plpgsql;


ALTER PROCEDURAL LANGUAGE plpgsql OWNER TO postgres;

SET search_path = dorothy, pg_catalog;

--
-- Name: dns_queries; Type: TYPE; Schema: dorothy; Owner: postgres
--

CREATE TYPE dns_queries AS ENUM (
    'query',
    'axfr'
);


ALTER TYPE dorothy.dns_queries OWNER TO postgres;

--
-- Name: ftp_types; Type: TYPE; Schema: dorothy; Owner: postgres
--

CREATE TYPE ftp_types AS ENUM (
    'active',
    'passive',
    'fxp'
);


ALTER TYPE dorothy.ftp_types OWNER TO postgres;

--
-- Name: http_methods; Type: TYPE; Schema: dorothy; Owner: postgres
--

CREATE TYPE http_methods AS ENUM (
    'head',
    'get',
    'post',
    'put',
    'delete',
    'trace',
    'options',
    'connect',
    'patch'
);


ALTER TYPE dorothy.http_methods OWNER TO postgres;

--
-- Name: layer4_protocols; Type: TYPE; Schema: dorothy; Owner: postgres
--

CREATE TYPE layer4_protocols AS ENUM (
    'tcp',
    'udp'
);


ALTER TYPE dorothy.layer4_protocols OWNER TO postgres;

--
-- Name: layer7_protocols; Type: TYPE; Schema: dorothy; Owner: postgres
--

CREATE TYPE layer7_protocols AS ENUM (
    'http',
    'irc',
    'dns',
    'smtp',
    'other'
);


ALTER TYPE dorothy.layer7_protocols OWNER TO postgres;

--
-- Name: sample_type; Type: TYPE; Schema: dorothy; Owner: postgres
--

CREATE TYPE sample_type AS ENUM (
    'mz',
    'pe',
    'elf'
);


ALTER TYPE dorothy.sample_type OWNER TO postgres;

--
-- Name: TYPE sample_type; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON TYPE sample_type IS 'Sample file type';


--
-- Name: sanbox_type; Type: TYPE; Schema: dorothy; Owner: postgres
--

CREATE TYPE sanbox_type AS ENUM (
    'virtual',
    'phisical',
    'mobile-virtual',
    'mobile-phisical',
    'external'
);


ALTER TYPE dorothy.sanbox_type OWNER TO postgres;

--
-- Name: sensor_type; Type: TYPE; Schema: dorothy; Owner: postgres
--

CREATE TYPE sensor_type AS ENUM (
    'low_honey',
    'high_honey',
    'mwcollect'
);


ALTER TYPE dorothy.sensor_type OWNER TO postgres;

--
-- Name: sensor_type2; Type: TYPE; Schema: dorothy; Owner: postgres
--

CREATE TYPE sensor_type2 AS ENUM (
    'lowint-honeypot',
    'highint-honeypot',
    'unknow',
    'client-honeypot',
    'external-source'
);


ALTER TYPE dorothy.sensor_type2 OWNER TO postgres;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: analyses; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE analyses (
    id integer NOT NULL,
    sample character(64) NOT NULL,
    sandbox integer NOT NULL,
    traffic_dump character(64) NOT NULL,
    date timestamp without time zone
);


ALTER TABLE dorothy.analyses OWNER TO postgres;

--
-- Name: analyses_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE analyses_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.analyses_id_seq OWNER TO postgres;

--
-- Name: analyses_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE analyses_id_seq OWNED BY analyses.id;


--
-- Name: analyses_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('analyses_id_seq', 1, true);


--
-- Name: samples; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE samples (
    hash character(64) NOT NULL,
    size integer NOT NULL,
    type sample_type,
    path character(256),
    filename character(256),
    md5 character(64),
    long_type character varying,
    CONSTRAINT size_notneg CHECK ((size >= 0))
);


ALTER TABLE dorothy.samples OWNER TO postgres;

--
-- Name: TABLE samples; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON TABLE samples IS 'Acquired samples';


--
-- Name: COLUMN samples.hash; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN samples.hash IS 'SHA256 checksum hash';


--
-- Name: COLUMN samples.size; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN samples.size IS 'Sample size';


--
-- Name: COLUMN samples.type; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN samples.type IS 'Sample type';


--
-- Name: CONSTRAINT size_notneg ON samples; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON CONSTRAINT size_notneg ON samples IS 'Sample size must not be negative';


--
-- Name: traffic_dumps; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE traffic_dumps (
    hash character(64) NOT NULL,
    size integer NOT NULL,
    pcapr_id character(64),
    "binary" character varying,
    parsed boolean
);


ALTER TABLE dorothy.traffic_dumps OWNER TO postgres;

--
-- Name: COLUMN traffic_dumps.hash; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN traffic_dumps.hash IS 'SHA256 checksum hash';


--
-- Name: analysis_resume_view; Type: VIEW; Schema: dorothy; Owner: postgres
--

CREATE VIEW analysis_resume_view AS
    SELECT analyses.id, samples.filename, samples.md5, samples.long_type, analyses.date, traffic_dumps.parsed FROM traffic_dumps, samples, analyses WHERE ((analyses.sample = samples.hash) AND (analyses.traffic_dump = traffic_dumps.hash)) ORDER BY analyses.id DESC;


ALTER TABLE dorothy.analysis_resume_view OWNER TO postgres;

--
-- Name: appdata_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE appdata_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.appdata_id_seq OWNER TO postgres;

--
-- Name: appdata_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('appdata_id_seq', 1, true);


--
-- Name: asns; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE asns (
    handle character varying(10) NOT NULL,
    owner character varying(15),
    country character(2),
    confidence integer,
    id integer NOT NULL
);


ALTER TABLE dorothy.asns OWNER TO postgres;

--
-- Name: TABLE asns; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON TABLE asns IS 'Autonomous systems';


--
-- Name: asns_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE asns_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.asns_id_seq OWNER TO postgres;

--
-- Name: asns_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE asns_id_seq OWNED BY asns.id;


--
-- Name: asns_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('asns_id_seq', 1, false);


--
-- Name: dns_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE dns_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.dns_id_seq OWNER TO postgres;

--
-- Name: dns_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('dns_id_seq', 1, true);


--
-- Name: dns_data; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE dns_data (
    id integer DEFAULT nextval('dns_id_seq'::regclass) NOT NULL,
    name character varying(255),
    class integer,
    qry boolean NOT NULL,
    ttl integer,
    flow integer NOT NULL,
    address inet,
    data character varying(255),
    type integer,
    is_sinkholed boolean
);


ALTER TABLE dorothy.dns_data OWNER TO postgres;

--
-- Name: COLUMN dns_data.address; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN dns_data.address IS 'type A answer data ';


--
-- Name: COLUMN dns_data.data; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN dns_data.data IS 'in the case it is an answer different from TYPE A ';


--
-- Name: flows; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE flows (
    source inet NOT NULL,
    dest inet NOT NULL,
    srcport integer,
    dstport integer,
    size integer NOT NULL,
    traffic_dump character(64),
    packets integer DEFAULT 0,
    id bigint NOT NULL,
    ip_protocol integer DEFAULT 1 NOT NULL,
    service character(64) DEFAULT 0,
    title character(256),
    content character(128) DEFAULT 0,
    duration double precision DEFAULT 0,
    "time" double precision,
    relative_id integer NOT NULL
);


ALTER TABLE dorothy.flows OWNER TO postgres;

--
-- Name: COLUMN flows.packets; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN flows.packets IS 'Number of the packets involved in the flow';


--
-- Name: COLUMN flows.service; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN flows.service IS 'flow service';


--
-- Name: COLUMN flows.title; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN flows.title IS 'Title of the flow';


--
-- Name: COLUMN flows.content; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN flows.content IS 'Link to pcapr-local RESTful platform . (URL)';


--
-- Name: COLUMN flows."time"; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN flows."time" IS 'Relative time (from the beginning) of the flow';


--
-- Name: host_ips; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE host_ips (
    ip inet NOT NULL,
    geoinfo integer,
    sbl integer,
    uptime time without time zone,
    is_online boolean,
    whois integer,
    zone text,
    last_update timestamp without time zone,
    id integer NOT NULL,
    dns_name integer,
    migrated_from integer
);


ALTER TABLE dorothy.host_ips OWNER TO postgres;

--
-- Name: host_roles; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE host_roles (
    role integer NOT NULL,
    host_ip inet NOT NULL
);


ALTER TABLE dorothy.host_roles OWNER TO postgres;

--
-- Name: irc_data; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE irc_data (
    id integer NOT NULL,
    flow integer NOT NULL,
    data bytea,
    incoming boolean NOT NULL
);


ALTER TABLE dorothy.irc_data OWNER TO postgres;

--
-- Name: roles; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE roles (
    id integer NOT NULL,
    type character varying(10),
    comment character varying
);


ALTER TABLE dorothy.roles OWNER TO postgres;

--
-- Name: ccprofile_view3; Type: VIEW; Schema: dorothy; Owner: postgres
--

CREATE VIEW ccprofile_view3 AS
    SELECT DISTINCT host_ips.id AS hostid, host_ips.ip, flows.dstport, traffic_dumps.hash, irc_data.id, roles.type, dns_data.name, irc_data.data FROM roles, host_roles, host_ips, dns_data, flows, irc_data, traffic_dumps WHERE (((((((((roles.id = host_roles.role) AND (host_roles.host_ip = host_ips.ip)) AND (dns_data.id = host_ips.dns_name)) AND (flows.dest = host_ips.ip)) AND (flows.traffic_dump = traffic_dumps.hash)) AND (irc_data.flow = flows.id)) AND (irc_data.incoming = false)) AND (host_ips.is_online = true)) AND ((roles.type)::text = 'cc-irc'::text)) ORDER BY irc_data.id, host_ips.id, host_ips.ip, flows.dstport, traffic_dumps.hash, roles.type, dns_data.name, irc_data.data;


ALTER TABLE dorothy.ccprofile_view3 OWNER TO postgres;

--
-- Name: connections_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE connections_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.connections_id_seq OWNER TO postgres;

--
-- Name: connections_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE connections_id_seq OWNED BY flows.id;


--
-- Name: connections_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('connections_id_seq', 1, true);


--
-- Name: downloads; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE downloads (
    sample character(256) NOT NULL,
    flow integer NOT NULL,
    path character(128) NOT NULL,
    filename character varying
);


ALTER TABLE dorothy.downloads OWNER TO postgres;

--
-- Name: TABLE downloads; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON TABLE downloads IS 'Downloaded sample sighting';


--
-- Name: emails; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE emails (
    "from" character(64),
    "to" character(64),
    subject character(128),
    data bytea,
    id integer NOT NULL,
    flow bigint NOT NULL,
    hcmd character varying,
    hcont character varying,
    rcode interval,
    rcont character varying
);


ALTER TABLE dorothy.emails OWNER TO postgres;

--
-- Name: emails_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE emails_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.emails_id_seq OWNER TO postgres;

--
-- Name: emails_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE emails_id_seq OWNED BY emails.id;


--
-- Name: emails_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('emails_id_seq', 1, true);


--
-- Name: ftp_data; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE ftp_data (
    id integer DEFAULT nextval('appdata_id_seq'::regclass) NOT NULL,
    banner text,
    "user" character varying(50),
    password character varying(50),
    type ftp_types,
    is_ssl boolean,
    size integer,
    data bytea
);


ALTER TABLE dorothy.ftp_data OWNER TO postgres;

--
-- Name: geoinfo; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE geoinfo (
    id integer NOT NULL,
    longlat point,
    country character(2),
    city character varying(255),
    "last-update" timestamp without time zone,
    asn integer
);


ALTER TABLE dorothy.geoinfo OWNER TO postgres;

--
-- Name: COLUMN geoinfo.longlat; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN geoinfo.longlat IS 'Spatial location (longitude, latitude)';


--
-- Name: geoinfo_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE geoinfo_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.geoinfo_id_seq OWNER TO postgres;

--
-- Name: geoinfo_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE geoinfo_id_seq OWNED BY geoinfo.id;


--
-- Name: geoinfo_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('geoinfo_id_seq', 1, true);


--
-- Name: host_ips_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE host_ips_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.host_ips_id_seq OWNER TO postgres;

--
-- Name: host_ips_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE host_ips_id_seq OWNED BY host_ips.id;


--
-- Name: host_ips_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('host_ips_id_seq', 1, true);


--
-- Name: http_data; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE http_data (
    id integer DEFAULT nextval('appdata_id_seq'::regclass) NOT NULL,
    method http_methods NOT NULL,
    url text,
    size integer,
    is_ssl boolean,
    flow integer NOT NULL,
    data bytea
);


ALTER TABLE dorothy.http_data OWNER TO postgres;

--
-- Name: http_headers; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE http_headers (
    http_data integer NOT NULL,
    key character varying(255) NOT NULL,
    value character varying(255)
);


ALTER TABLE dorothy.http_headers OWNER TO postgres;

--
-- Name: irc_data_connection_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE irc_data_connection_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.irc_data_connection_seq OWNER TO postgres;

--
-- Name: irc_data_connection_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE irc_data_connection_seq OWNED BY irc_data.flow;


--
-- Name: irc_data_connection_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('irc_data_connection_seq', 1, true);


--
-- Name: malwares; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE malwares (
    bin character(64) NOT NULL,
    family character(64) NOT NULL,
    vendor character(64),
    version character(16),
    rate character(8),
    update integer,
    detected boolean NOT NULL
);


ALTER TABLE dorothy.malwares OWNER TO postgres;

--
-- Name: reports; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE reports (
    id integer NOT NULL,
    sandbox integer NOT NULL,
    sample character(64) NOT NULL,
    data text NOT NULL
);


ALTER TABLE dorothy.reports OWNER TO postgres;

--
-- Name: reports_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE reports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.reports_id_seq OWNER TO postgres;

--
-- Name: reports_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE reports_id_seq OWNED BY reports.id;


--
-- Name: reports_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('reports_id_seq', 1, false);


--
-- Name: roles_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.roles_id_seq OWNER TO postgres;

--
-- Name: roles_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE roles_id_seq OWNED BY roles.id;


--
-- Name: roles_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('roles_id_seq', 1, false);


--
-- Name: sandboxes; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE sandboxes (
    id integer NOT NULL,
    hostname character varying(30) NOT NULL,
    type sanbox_type NOT NULL,
    "OS" character varying NOT NULL,
    version character varying,
    os_lang character(4),
    ipaddress inet,
    username character varying NOT NULL,
    password character varying,
    is_available boolean DEFAULT false NOT NULL
);


ALTER TABLE dorothy.sandboxes OWNER TO postgres;

--
-- Name: sandboxes_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE sandboxes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.sandboxes_id_seq OWNER TO postgres;

--
-- Name: sandboxes_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE sandboxes_id_seq OWNED BY sandboxes.id;


--
-- Name: sandboxes_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('sandboxes_id_seq', 1, true);


--
-- Name: sensors; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE sensors (
    id integer NOT NULL,
    name character varying(40) NOT NULL,
    host integer NOT NULL,
    type sensor_type2 NOT NULL
);


ALTER TABLE dorothy.sensors OWNER TO postgres;

--
-- Name: TABLE sensors; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON TABLE sensors IS 'Malware sensors';


--
-- Name: sensors_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE sensors_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.sensors_id_seq OWNER TO postgres;

--
-- Name: sensors_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE sensors_id_seq OWNED BY sensors.id;


--
-- Name: sensors_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('sensors_id_seq', 1, false);


--
-- Name: sightings; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE sightings (
    sample character(64) NOT NULL,
    sensor integer NOT NULL,
    date timestamp without time zone NOT NULL,
    traffic_dump character(64)
);


ALTER TABLE dorothy.sightings OWNER TO postgres;

--
-- Name: TABLE sightings; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON TABLE sightings IS 'Malware sample sightings on sensors';


--
-- Name: COLUMN sightings.sample; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN sightings.sample IS 'Sample hash';


--
-- Name: COLUMN sightings.sensor; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN sightings.sensor IS '
';


--
-- Name: whois; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE whois (
    id integer NOT NULL,
    query character varying(255),
    data text,
    abuse character varying(255),
    "last-update" timestamp without time zone
);


ALTER TABLE dorothy.whois OWNER TO postgres;

--
-- Name: COLUMN whois.abuse; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN whois.abuse IS 'Abuse email address';


--
-- Name: whois_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE whois_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.whois_id_seq OWNER TO postgres;

--
-- Name: whois_id_seq; Type: SEQUENCE OWNED BY; Schema: dorothy; Owner: postgres
--

ALTER SEQUENCE whois_id_seq OWNED BY whois.id;


--
-- Name: whois_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('whois_id_seq', 1, false);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY analyses ALTER COLUMN id SET DEFAULT nextval('analyses_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY asns ALTER COLUMN id SET DEFAULT nextval('asns_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY emails ALTER COLUMN id SET DEFAULT nextval('emails_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY flows ALTER COLUMN id SET DEFAULT nextval('connections_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY geoinfo ALTER COLUMN id SET DEFAULT nextval('geoinfo_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY host_ips ALTER COLUMN id SET DEFAULT nextval('host_ips_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY irc_data ALTER COLUMN id SET DEFAULT nextval('irc_data_connection_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY reports ALTER COLUMN id SET DEFAULT nextval('reports_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY roles ALTER COLUMN id SET DEFAULT nextval('roles_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY sandboxes ALTER COLUMN id SET DEFAULT nextval('sandboxes_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY sensors ALTER COLUMN id SET DEFAULT nextval('sensors_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY whois ALTER COLUMN id SET DEFAULT nextval('whois_id_seq'::regclass);


--
-- Data for Name: analyses; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY analyses (id, sample, sandbox, traffic_dump, date) FROM stdin;
\.


--
-- Data for Name: asns; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY asns (handle, owner, country, confidence, id) FROM stdin;
\.


--
-- Data for Name: dns_data; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY dns_data (id, name, class, qry, ttl, flow, address, data, type, is_sinkholed) FROM stdin;
\.


--
-- Data for Name: downloads; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY downloads (sample, flow, path, filename) FROM stdin;
\.


--
-- Data for Name: emails; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY emails ("from", "to", subject, data, id, flow, hcmd, hcont, rcode, rcont) FROM stdin;
\.


--
-- Data for Name: flows; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY flows (source, dest, srcport, dstport, size, traffic_dump, packets, id, ip_protocol, service, title, content, duration, "time", relative_id) FROM stdin;
\.


--
-- Data for Name: ftp_data; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY ftp_data (id, banner, "user", password, type, is_ssl, size, data) FROM stdin;
\.


--
-- Data for Name: geoinfo; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY geoinfo (id, longlat, country, city, "last-update", asn) FROM stdin;
\.


--
-- Data for Name: host_ips; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY host_ips (ip, geoinfo, sbl, uptime, is_online, whois, zone, last_update, id, dns_name, migrated_from) FROM stdin;
\.


--
-- Data for Name: host_roles; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY host_roles (role, host_ip) FROM stdin;
\.


--
-- Data for Name: http_data; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY http_data (id, method, url, size, is_ssl, flow, data) FROM stdin;
\.


--
-- Data for Name: http_headers; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY http_headers (http_data, key, value) FROM stdin;
\.


--
-- Data for Name: irc_data; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY irc_data (id, flow, data, incoming) FROM stdin;
\.


--
-- Data for Name: malwares; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY malwares (bin, family, vendor, version, rate, update, detected) FROM stdin;
\.


--
-- Data for Name: reports; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY reports (id, sandbox, sample, data) FROM stdin;
\.


--
-- Data for Name: roles; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY roles (id, type, comment) FROM stdin;
0	honeypot	\N
1	cc-irc	\N
2	SPAM	\N
3	cc-drop	\N
5	cc-support	\N
4	unknown	\N
\.


--
-- Data for Name: samples; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY samples (hash, size, type, path, filename, md5, long_type) FROM stdin;
\.


--
-- Data for Name: sandboxes; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY sandboxes (id, hostname, type, "OS", version, os_lang, ipaddress, username, password, is_available) FROM stdin;
\.


--
-- Data for Name: sensors; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY sensors (id, name, host, type) FROM stdin;
0	hp1-dionaea	0	lowint-honeypot
2	userinput	0	unknow
1	ztracker	0	external-source
\.


--
-- Data for Name: sightings; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY sightings (sample, sensor, date, traffic_dump) FROM stdin;
\.


--
-- Data for Name: traffic_dumps; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY traffic_dumps (hash, size, pcapr_id, "binary", parsed) FROM stdin;
\.


--
-- Data for Name: whois; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY whois (id, query, data, abuse, "last-update") FROM stdin;
\.


--
-- Name: asns_handle_uq; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY asns
    ADD CONSTRAINT asns_handle_uq UNIQUE (handle);


--
-- Name: CONSTRAINT asns_handle_uq ON asns; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON CONSTRAINT asns_handle_uq ON asns IS 'AS handle must be unique';


--
-- Name: asns_pk; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY asns
    ADD CONSTRAINT asns_pk PRIMARY KEY (id);


--
-- Name: dns_data_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY dns_data
    ADD CONSTRAINT dns_data_pkey PRIMARY KEY (id);


--
-- Name: ftp_data_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY ftp_data
    ADD CONSTRAINT ftp_data_pkey PRIMARY KEY (id);


--
-- Name: geoinfo_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY geoinfo
    ADD CONSTRAINT geoinfo_pkey PRIMARY KEY (id);


--
-- Name: hash; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY samples
    ADD CONSTRAINT hash PRIMARY KEY (hash);


--
-- Name: http_data_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY http_data
    ADD CONSTRAINT http_data_pkey PRIMARY KEY (id);


--
-- Name: http_headers_pk; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY http_headers
    ADD CONSTRAINT http_headers_pk PRIMARY KEY (http_data, key);


--
-- Name: id; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY analyses
    ADD CONSTRAINT id PRIMARY KEY (id);


--
-- Name: id_pk; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY emails
    ADD CONSTRAINT id_pk PRIMARY KEY (id);


--
-- Name: ip_uniq; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY host_ips
    ADD CONSTRAINT ip_uniq UNIQUE (ip);


--
-- Name: pk_connection; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY flows
    ADD CONSTRAINT pk_connection PRIMARY KEY (id);


--
-- Name: pk_host_ips; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY host_ips
    ADD CONSTRAINT pk_host_ips PRIMARY KEY (ip, id);


--
-- Name: pk_irc; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY irc_data
    ADD CONSTRAINT pk_irc PRIMARY KEY (id);


--
-- Name: reports_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: roles_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: sandboxes_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY sandboxes
    ADD CONSTRAINT sandboxes_pkey PRIMARY KEY (id);


--
-- Name: sensors_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY sensors
    ADD CONSTRAINT sensors_pkey PRIMARY KEY (id);

--
-- Name: traffic_dumps_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY traffic_dumps
    ADD CONSTRAINT traffic_dumps_pkey PRIMARY KEY (hash);


--
-- Name: uniq_sandbox; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY sandboxes
    ADD CONSTRAINT uniq_sandbox UNIQUE (ipaddress);


--
-- Name: whois_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY whois
    ADD CONSTRAINT whois_pkey PRIMARY KEY (id);


--
-- Name: fki_bin; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_bin ON malwares USING btree (bin);


--
-- Name: fki_connection; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_connection ON http_data USING btree (flow);


--
-- Name: fki_dest_ip; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_dest_ip ON flows USING btree (dest);


--
-- Name: fki_dns; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_dns ON host_ips USING btree (dns_name);


--
-- Name: fki_dumps; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_dumps ON flows USING btree (traffic_dump);


--
-- Name: fki_email; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_email ON emails USING btree (flow);


--
-- Name: fki_flow; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_flow ON downloads USING btree (flow);


--
-- Name: fki_flows; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_flows ON dns_data USING btree (flow);


--
-- Name: fki_host; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_host ON host_roles USING btree (host_ip);


--
-- Name: fki_irc; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_irc ON irc_data USING btree (flow);


--
-- Name: fki_sample; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_sample ON analyses USING btree (sample);


--
-- Name: fki_sandbox; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_sandbox ON analyses USING btree (sandbox);


--
-- Name: fki_shash; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_shash ON reports USING btree (sample);


--
-- Name: fki_tdumps; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_tdumps ON analyses USING btree (traffic_dump);


--
-- Name: dest_ip; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY flows
    ADD CONSTRAINT dest_ip FOREIGN KEY (dest) REFERENCES host_ips(ip);


--
-- Name: dns; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY host_ips
    ADD CONSTRAINT dns FOREIGN KEY (dns_name) REFERENCES dns_data(id);


--
-- Name: dumps; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY flows
    ADD CONSTRAINT dumps FOREIGN KEY (traffic_dump) REFERENCES traffic_dumps(hash);


--
-- Name: fk_bin; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY malwares
    ADD CONSTRAINT fk_bin FOREIGN KEY (bin) REFERENCES samples(hash);


--
-- Name: fk_email; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY emails
    ADD CONSTRAINT fk_email FOREIGN KEY (flow) REFERENCES flows(id);


--
-- Name: fk_flow; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY http_data
    ADD CONSTRAINT fk_flow FOREIGN KEY (flow) REFERENCES flows(id);


--
-- Name: fk_flow; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY downloads
    ADD CONSTRAINT fk_flow FOREIGN KEY (flow) REFERENCES flows(id);


--
-- Name: fk_irc; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY irc_data
    ADD CONSTRAINT fk_irc FOREIGN KEY (flow) REFERENCES flows(id);


--
-- Name: flows; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY dns_data
    ADD CONSTRAINT flows FOREIGN KEY (flow) REFERENCES flows(id);


--
-- Name: geoinfo_fk; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY host_ips
    ADD CONSTRAINT geoinfo_fk FOREIGN KEY (geoinfo) REFERENCES geoinfo(id);


--
-- Name: host; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY host_roles
    ADD CONSTRAINT host FOREIGN KEY (host_ip) REFERENCES host_ips(ip);


--
-- Name: role_fkey; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY host_roles
    ADD CONSTRAINT role_fkey FOREIGN KEY (role) REFERENCES roles(id);


--
-- Name: samples; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY analyses
    ADD CONSTRAINT samples FOREIGN KEY (sample) REFERENCES samples(hash);


--
-- Name: samples; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY sightings
    ADD CONSTRAINT samples FOREIGN KEY (sample) REFERENCES samples(hash);


--
-- Name: sensor_fkey; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY sightings
    ADD CONSTRAINT sensor_fkey FOREIGN KEY (sensor) REFERENCES sensors(id);


--
-- Name: shash; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY reports
    ADD CONSTRAINT shash FOREIGN KEY (sample) REFERENCES samples(hash);


--
-- Name: tdumps; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY analyses
    ADD CONSTRAINT tdumps FOREIGN KEY (traffic_dump) REFERENCES traffic_dumps(hash);


--
-- Name: whois_fk; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY host_ips
    ADD CONSTRAINT whois_fk FOREIGN KEY (whois) REFERENCES whois(id);


--
-- Name: dorothy; Type: ACL; Schema: -; Owner: postgres
--

REVOKE ALL ON SCHEMA dorothy FROM PUBLIC;
REVOKE ALL ON SCHEMA dorothy FROM postgres;
GRANT ALL ON SCHEMA dorothy TO postgres;
GRANT ALL ON SCHEMA dorothy TO PUBLIC;


--
-- PostgreSQL database dump complete
--

