CREATE TABLE dorothy.sys_procs
(
  analysis_id integer NOT NULL,
  pid integer NOT NULL,
  "name" character varying,
  "owner" character varying,
  "cmdLine" character varying,
  "startTime" timestamp without time zone,
  "endTime" timestamp without time zone,
  "exitCode" integer,
  CONSTRAINT "procs-pk" PRIMARY KEY (analysis_id, pid),
  CONSTRAINT "anal_id-fk" FOREIGN KEY (analysis_id)
      REFERENCES dorothy.analyses (id) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
WITH (
  OIDS=FALSE
);
ALTER TABLE dorothy.sys_procs OWNER TO postgres;
