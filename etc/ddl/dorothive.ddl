--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

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
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


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
-- Name: queue_status; Type: TYPE; Schema: dorothy; Owner: postgres
--

CREATE TYPE queue_status AS ENUM (
    'cancelled',
    'pending',
    'analysed',
    'processing',
    'error'
);


ALTER TYPE dorothy.queue_status OWNER TO postgres;

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
    date timestamp without time zone,
    queue_id bigint NOT NULL
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
-- Name: queue_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE queue_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.queue_id_seq OWNER TO postgres;

--
-- Name: analysis_queue; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE analysis_queue (
    id bigint DEFAULT nextval('queue_id_seq'::regclass) NOT NULL,
    date timestamp without time zone NOT NULL,
    "binary" character(64),
    priority integer DEFAULT 0 NOT NULL,
    profile character varying DEFAULT 'default'::character varying NOT NULL,
    source character varying,
    "user" character varying,
    filename character varying NOT NULL,
    status queue_status,
    sighting bigint
);


ALTER TABLE dorothy.analysis_queue OWNER TO postgres;

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
-- Name: av_signs; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE av_signs (
    id bigint NOT NULL,
    av_name character varying NOT NULL,
    signature character varying NOT NULL,
    version character varying NOT NULL,
    updated character varying
);


ALTER TABLE dorothy.av_signs OWNER TO postgres;

--
-- Name: cfg_chk_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE cfg_chk_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.cfg_chk_id_seq OWNER TO postgres;

--
-- Name: cfg_chk; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE cfg_chk (
    id bigint DEFAULT nextval('cfg_chk_id_seq'::regclass) NOT NULL,
    conf_file character varying,
    md5_chksum character(32) NOT NULL,
    added timestamp without time zone,
    last_modified timestamp without time zone
);


ALTER TABLE dorothy.cfg_chk OWNER TO postgres;

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
-- Name: email_receivers; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE email_receivers (
    address character varying NOT NULL,
    email_id bigint NOT NULL,
    mail_field character(5) NOT NULL
);


ALTER TABLE dorothy.email_receivers OWNER TO postgres;

--
-- Name: emails; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE emails (
    "from" character varying(64),
    subject character varying(128),
    data bytea,
    id integer NOT NULL,
    flow bigint,
    hcmd character varying,
    hcont character varying,
    rcode interval,
    rcont character varying,
    date timestamp without time zone,
    message_id character varying,
    has_attachment boolean,
    charset character varying,
    body_sha256 character(64),
    forwarded_by bigint
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
-- Name: host_roles; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE host_roles (
    role integer NOT NULL,
    host_ip inet NOT NULL
);


ALTER TABLE dorothy.host_roles OWNER TO postgres;

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
-- Name: malwares_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE malwares_id_seq
    START WITH 0
    INCREMENT BY 1
    MINVALUE 0
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.malwares_id_seq OWNER TO postgres;

--
-- Name: malwares; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE malwares (
    bin character(64) NOT NULL,
    rate character(8),
    detected boolean NOT NULL,
    date timestamp without time zone,
    link character varying,
    id bigint DEFAULT nextval('malwares_id_seq'::regclass) NOT NULL
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
-- Name: roles; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE roles (
    id integer NOT NULL,
    type character varying(10),
    comment character varying
);


ALTER TABLE dorothy.roles OWNER TO postgres;

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
-- Name: samples; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE samples (
    sha256 character(64) NOT NULL,
    size integer NOT NULL,
    path character varying(256),
    filename character varying(256),
    md5 character(32),
    long_type character varying,
    CONSTRAINT size_notneg CHECK ((size >= 0))
);


ALTER TABLE dorothy.samples OWNER TO postgres;

--
-- Name: TABLE samples; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON TABLE samples IS 'Acquired samples';


--
-- Name: COLUMN samples.sha256; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN samples.sha256 IS 'SHA256 checksum hash';


--
-- Name: COLUMN samples.size; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN samples.size IS 'Sample size';


--
-- Name: CONSTRAINT size_notneg ON samples; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON CONSTRAINT size_notneg ON samples IS 'Sample size must not be negative';


--
-- Name: sandboxes; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE sandboxes (
    id integer NOT NULL,
    hostname character varying(30) NOT NULL,
    sandbox_type sanbox_type NOT NULL,
    os character varying NOT NULL,
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
-- Name: sightings_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE sightings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.sightings_id_seq OWNER TO postgres;

--
-- Name: sightings; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE sightings (
    sample character(64) NOT NULL,
    sensor integer NOT NULL,
    date timestamp without time zone NOT NULL,
    id bigint DEFAULT nextval('sightings_id_seq'::regclass) NOT NULL,
    src_email bigint
);


ALTER TABLE dorothy.sightings OWNER TO postgres;

--
-- Name: TABLE sightings; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON TABLE sightings IS 'Malware sample sightings on sources';


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
-- Name: sources_id_seq; Type: SEQUENCE; Schema: dorothy; Owner: postgres
--

CREATE SEQUENCE sources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE dorothy.sources_id_seq OWNER TO postgres;

--
-- Name: sources; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE sources (
    id integer DEFAULT nextval('sources_id_seq'::regclass) NOT NULL,
    sname character varying NOT NULL,
    stype character varying NOT NULL,
    disabled boolean DEFAULT false,
    host character varying,
    geo integer,
    added timestamp without time zone,
    last_modified timestamp without time zone,
    localdir character varying
);


ALTER TABLE dorothy.sources OWNER TO postgres;

--
-- Name: sys_procs; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE sys_procs (
    analysis_id integer NOT NULL,
    pid integer NOT NULL,
    name character varying,
    owner character varying,
    "cmdLine" character varying,
    "startTime" timestamp without time zone,
    "endTime" timestamp without time zone,
    "exitCode" integer
);


ALTER TABLE dorothy.sys_procs OWNER TO postgres;

--
-- Name: traffic_dumps; Type: TABLE; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE TABLE traffic_dumps (
    sha256 character(64) NOT NULL,
    size integer NOT NULL,
    pcapr_id character(32),
    "binary" character varying,
    parsed boolean
);


ALTER TABLE dorothy.traffic_dumps OWNER TO postgres;

--
-- Name: COLUMN traffic_dumps.sha256; Type: COMMENT; Schema: dorothy; Owner: postgres
--

COMMENT ON COLUMN traffic_dumps.sha256 IS 'SHA256 checksum hash';


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

ALTER TABLE ONLY whois ALTER COLUMN id SET DEFAULT nextval('whois_id_seq'::regclass);


--
-- Data for Name: analyses; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY analyses (id, sample, sandbox, traffic_dump, date, queue_id) FROM stdin;
\.


--
-- Name: analyses_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('analyses_id_seq', 1, false);


--
-- Data for Name: analysis_queue; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY analysis_queue (id, date, "binary", priority, profile, source, "user", filename, status, sighting) FROM stdin;
\.


--
-- Name: appdata_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('appdata_id_seq', 1, false);


--
-- Data for Name: asns; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY asns (handle, owner, country, confidence, id) FROM stdin;
\.


--
-- Name: asns_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('asns_id_seq', 1, false);


--
-- Data for Name: av_signs; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY av_signs (id, av_name, signature, version, updated) FROM stdin;
\.


--
-- Data for Name: cfg_chk; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY cfg_chk (id, conf_file, md5_chksum, added, last_modified) FROM stdin;
\.


--
-- Name: cfg_chk_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('cfg_chk_id_seq', 1, false);


--
-- Name: connections_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('connections_id_seq', 1, false);


--
-- Data for Name: dns_data; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY dns_data (id, name, class, qry, ttl, flow, address, data, type, is_sinkholed) FROM stdin;
\.


--
-- Name: dns_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('dns_id_seq', 1, false);


--
-- Data for Name: downloads; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY downloads (sample, flow, path, filename) FROM stdin;
\.


--
-- Data for Name: email_receivers; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY email_receivers (address, email_id, mail_field) FROM stdin;
\.


--
-- Data for Name: emails; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY emails ("from", subject, data, id, flow, hcmd, hcont, rcode, rcont, date, message_id, has_attachment, charset, body_sha256, forwarded_by) FROM stdin;
\.


--
-- Name: emails_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('emails_id_seq', 1, false);


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
-- Name: geoinfo_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('geoinfo_id_seq', 1, false);


--
-- Data for Name: host_ips; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY host_ips (ip, geoinfo, sbl, uptime, is_online, whois, zone, last_update, id, dns_name, migrated_from) FROM stdin;
\.


--
-- Name: host_ips_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('host_ips_id_seq', 1, false);


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
-- Name: irc_data_connection_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('irc_data_connection_seq', 1, false);


--
-- Data for Name: malwares; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY malwares (bin, rate, detected, date, link, id) FROM stdin;
\.


--
-- Name: malwares_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('malwares_id_seq', 0, false);


--
-- Name: queue_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('queue_id_seq', 1, false);


--
-- Data for Name: reports; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY reports (id, sandbox, sample, data) FROM stdin;
\.


--
-- Name: reports_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('reports_id_seq', 1, false);


--
-- Data for Name: roles; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY roles (id, type, comment) FROM stdin;
0	honeypot	\N
1	cc-irc	\N
2	SPAM	\N
3	cc-drop	\N
4	unknown	\N
5	cc-support	\N
6	phishing	\N
\.


--
-- Name: roles_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('roles_id_seq', 1, false);


--
-- Data for Name: samples; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY samples (sha256, size, path, filename, md5, long_type) FROM stdin;
\.


--
-- Data for Name: sandboxes; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY sandboxes (id, hostname, sandbox_type, os, version, os_lang, ipaddress, username, password, is_available) FROM stdin;
\.


--
-- Name: sandboxes_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('sandboxes_id_seq', 1, false);


--
-- Data for Name: sightings; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY sightings (sample, sensor, date, id, src_email) FROM stdin;
\.


--
-- Name: sightings_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('sightings_id_seq', 1, false);


--
-- Data for Name: sources; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY sources (id, sname, stype, disabled, host, geo, added, last_modified, localdir) FROM stdin;
\.


--
-- Name: sources_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('sources_id_seq', 1, false);


--
-- Data for Name: sys_procs; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY sys_procs (analysis_id, pid, name, owner, "cmdLine", "startTime", "endTime", "exitCode") FROM stdin;
\.


--
-- Data for Name: traffic_dumps; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY traffic_dumps (sha256, size, pcapr_id, "binary", parsed) FROM stdin;
EMPTYPCAP                                                       	0	fffffff                         	ffff	t
\.


--
-- Data for Name: whois; Type: TABLE DATA; Schema: dorothy; Owner: postgres
--

COPY whois (id, query, data, abuse, "last-update") FROM stdin;
\.


--
-- Name: whois_id_seq; Type: SEQUENCE SET; Schema: dorothy; Owner: postgres
--

SELECT pg_catalog.setval('whois_id_seq', 1, false);


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
-- Name: av_signs_pk; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY av_signs
    ADD CONSTRAINT av_signs_pk PRIMARY KEY (id, av_name);


--
-- Name: cfg_chk_pk_id; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY cfg_chk
    ADD CONSTRAINT cfg_chk_pk_id PRIMARY KEY (id);


--
-- Name: dns_data_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY dns_data
    ADD CONSTRAINT dns_data_pkey PRIMARY KEY (id);


--
-- Name: email_rcv_pk; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY email_receivers
    ADD CONSTRAINT email_rcv_pk PRIMARY KEY (address, email_id, mail_field);


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
-- Name: malwares_pk; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY malwares
    ADD CONSTRAINT malwares_pk PRIMARY KEY (id);


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
-- Name: procs-pk; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY sys_procs
    ADD CONSTRAINT "procs-pk" PRIMARY KEY (analysis_id, pid);


--
-- Name: queue_id_pk; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY analysis_queue
    ADD CONSTRAINT queue_id_pk PRIMARY KEY (id);


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
-- Name: sha256; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY samples
    ADD CONSTRAINT sha256 PRIMARY KEY (sha256);


--
-- Name: sightings_pk_id; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY sightings
    ADD CONSTRAINT sightings_pk_id PRIMARY KEY (id);


--
-- Name: sources_id_pk; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY sources
    ADD CONSTRAINT sources_id_pk PRIMARY KEY (id);


--
-- Name: traffic_dumps_pkey; Type: CONSTRAINT; Schema: dorothy; Owner: postgres; Tablespace: 
--

ALTER TABLE ONLY traffic_dumps
    ADD CONSTRAINT traffic_dumps_pkey PRIMARY KEY (sha256);


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
-- Name: fki_analysis_queue_fk_sighting_id; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_analysis_queue_fk_sighting_id ON analysis_queue USING btree (sighting);


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
-- Name: fki_email_rcv_fk_emails_id; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_email_rcv_fk_emails_id ON email_receivers USING btree (email_id);


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
-- Name: fki_queue_id_fk; Type: INDEX; Schema: dorothy; Owner: postgres; Tablespace: 
--

CREATE INDEX fki_queue_id_fk ON analyses USING btree (queue_id);


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
-- Name: anal_id-fk; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY sys_procs
    ADD CONSTRAINT "anal_id-fk" FOREIGN KEY (analysis_id) REFERENCES analyses(id);


--
-- Name: analysis_queue_fk_sighting_id; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY analysis_queue
    ADD CONSTRAINT analysis_queue_fk_sighting_id FOREIGN KEY (sighting) REFERENCES sightings(id);


--
-- Name: av_signs_fk; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY av_signs
    ADD CONSTRAINT av_signs_fk FOREIGN KEY (id) REFERENCES malwares(id);


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
    ADD CONSTRAINT dumps FOREIGN KEY (traffic_dump) REFERENCES traffic_dumps(sha256);


--
-- Name: email_rcv_fk_emails_id; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY email_receivers
    ADD CONSTRAINT email_rcv_fk_emails_id FOREIGN KEY (email_id) REFERENCES emails(id);


--
-- Name: fk_bin; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY malwares
    ADD CONSTRAINT fk_bin FOREIGN KEY (bin) REFERENCES samples(sha256);


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
-- Name: queue_id_fk; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY analyses
    ADD CONSTRAINT queue_id_fk FOREIGN KEY (queue_id) REFERENCES analysis_queue(id);


--
-- Name: role_fkey; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY host_roles
    ADD CONSTRAINT role_fkey FOREIGN KEY (role) REFERENCES roles(id);


--
-- Name: sample_fk; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY analysis_queue
    ADD CONSTRAINT sample_fk FOREIGN KEY ("binary") REFERENCES samples(sha256);


--
-- Name: samples; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY analyses
    ADD CONSTRAINT samples FOREIGN KEY (sample) REFERENCES samples(sha256);


--
-- Name: samples; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY sightings
    ADD CONSTRAINT samples FOREIGN KEY (sample) REFERENCES samples(sha256);


--
-- Name: shash; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY reports
    ADD CONSTRAINT shash FOREIGN KEY (sample) REFERENCES samples(sha256);


--
-- Name: sightings_fk_emails; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY sightings
    ADD CONSTRAINT sightings_fk_emails FOREIGN KEY (src_email) REFERENCES emails(id);


--
-- Name: sightings_fk_sources_id; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY sightings
    ADD CONSTRAINT sightings_fk_sources_id FOREIGN KEY (sensor) REFERENCES sources(id);


--
-- Name: tdumps; Type: FK CONSTRAINT; Schema: dorothy; Owner: postgres
--

ALTER TABLE ONLY analyses
    ADD CONSTRAINT tdumps FOREIGN KEY (traffic_dump) REFERENCES traffic_dumps(sha256);


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

