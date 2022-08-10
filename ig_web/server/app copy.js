const express = require('express');
const app = express();
const session = require('express-session');
const port = 3000
const fs = require('fs'); // fs:filesystem. 파일에 쉽게 접근할 수 있게 해주는 모듈

//세션 처리
app.use(session({
    secret: 'secret code', // 세션 키
    resave: false, //세션에 수정사항이 없더라도 세션을 다시 저장하는지에 대한 설정
    saveUninitialized: false, // 세션에 저장할 내역이 없더라도 다시 저장할건지에 대한 설정
    coockie: {
        secure: false,
        maxAge: 1000 * 60 * 60 // 쿠키 유효시간 1시간으로 설정 (단위: ms)
    }
}));

// 웹서버 생성
const server = app.listen(port, () => { // port:3000
    console.log(`Server started. port ${port}`);
});

// sql.js 파일 임포트 (쿼리)
// 다음 코드에서 sql이 다시 변경되므로, let으로 선언해줘야함. (const: 프로그램 실행 중 고정값, let: 수정되도 되는 변수)
let sql = require('./sql.js');

// sql.js 파일의 변경 정보 모니터링
fs.watchFile(__dirname + '/sql.js', (curr, prev) => { // __dirname: 현재 파일의 경로
    console.log('sql 변경 시 재시작없이 반영되도록 함.'); // 파일에 변경상황이 발견됐을 시 로그
    delete require.cache[require.resolve('./sql.js')]; // 캐시에 올라가있는 sql.js 정보 지움
    sql = require('./sql.js'); //다시 임포트

});

//DB 접속 정보
const db = {
    database: 'dev',
    connectionLimit: 10,
    host: 'localhost',
    user: 'root',
    password: 'mariadb'
};

// 위의 접속정보를 이용해 DB에 연동
const dbPool = require('mysql').createPool(db); // createPool(): db에 바로 연동시켜줌.


// /api/login으로 post 요청 시 여기로 타고옴.
app.post('/api/login', async (request, res) => {
    request.session['email'] = 'ellie@opcia.kr';
    res.send('ok');
});

// /api/logout으로 post 요청 시 여기로 타고옴.
app.post('/api/logout', async (request, res) => {
    request.session.destroy();
    res.send('ok');
});


// DB 데이터를 가지고 오거나 업데이트 해주는 기능 수행
// 위의 두 경로(/api/login, /api/logout)이 아닌 이름으로 요청 시, 여기로 타고옴.
// sql파일에 정의되어있는 쿼리를 이용하게 코드 짬.
app.post('/api/:alias', async (request, res) => {
    // 로그인 안된 상태인 경우, 에러메시지 출력.
    /*
    if(!request.session.email) {
        return res.status(401).send({
            error: 'You need to login.'
        });
    }*/
    try {
        res.send(await req.db(request.params.alias)); //요청(req)으로 들어오는 패킷의 alias 파라미터
    } catch (err) {
        // 에러났을 경우, 500에러와 함께 발생한 에러메시지(err) 띄움
        res.status(500).send({
            error: err
        });
    }
});


// req 함수 객체 생성
const req = {
    async db(alias, param = [], where = '') {
        // dbPool에 query() 함수를 이용해 mariadb에 직접 쿼리를 실행하고 데이터를 받아올 수 있음. 
        return new Promise((resolve, reject) => dbPool.query(sql[alias].query + where, param, (error, rows) => {
            if (error) {
                if (error.code != 'ER_DUP_ENTRY')
                    console.log(error);
                resolve({
                    error
                });
            } else resolve(rows);
        }));
    }
};



var req2 = require('request');

var headers = {
    'Content-Type': 'application/json'
};

var dataString = `
  {
    "aggs": {
      "2": {
        "terms": {
          "field": "rule.name",
          "order": {
            "_count": "desc"
          },
          "size": 50
        },
        "aggs": {
          "3": {
            "terms": {
              "field": "rule.category",
              "order": {
                "_count": "desc"
              },
              "size": 50
            }
          }
        }
      }
    },
    "size": 0,
    "fields": [
      {
        "field": "@timestamp",
        "format": "date_time"
      },
      {
        "field": "aws.cloudtrail.digest.end_time",
        "format": "date_time"
      },
      {
        "field": "aws.cloudtrail.digest.newest_event_time",
        "format": "date_time"
      },
      {
        "field": "aws.cloudtrail.digest.oldest_event_time",
        "format": "date_time"
      },
      {
        "field": "aws.cloudtrail.digest.start_time",
        "format": "date_time"
      },
      {
        "field": "aws.cloudtrail.user_identity.session_context.creation_date",
        "format": "date_time"
      },
      {
        "field": "azure.auditlogs.properties.activity_datetime",
        "format": "date_time"
      },
      {
        "field": "azure.enqueued_time",
        "format": "date_time"
      },
      {
        "field": "azure.signinlogs.properties.created_at",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.agentReceiptTime",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.deviceCustomDate1",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.deviceCustomDate2",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.deviceReceiptTime",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.endTime",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.fileCreateTime",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.fileModificationTime",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.flexDate1",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.managerReceiptTime",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.oldFileCreateTime",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.oldFileModificationTime",
        "format": "date_time"
      },
      {
        "field": "cef.extensions.startTime",
        "format": "date_time"
      },
      {
        "field": "checkpoint.subs_exp",
        "format": "date_time"
      },
      {
        "field": "cisco.amp.threat_hunting.incident_end_time",
        "format": "date_time"
      },
      {
        "field": "cisco.amp.threat_hunting.incident_start_time",
        "format": "date_time"
      },
      {
        "field": "cisco.amp.timestamp_nanoseconds",
        "format": "date_time"
      },
      {
        "field": "crowdstrike.event.EndTimestamp",
        "format": "date_time"
      },
      {
        "field": "crowdstrike.event.IncidentEndTime",
        "format": "date_time"
      },
      {
        "field": "crowdstrike.event.IncidentStartTime",
        "format": "date_time"
      },
      {
        "field": "crowdstrike.event.ProcessEndTime",
        "format": "date_time"
      },
      {
        "field": "crowdstrike.event.ProcessStartTime",
        "format": "date_time"
      },
      {
        "field": "crowdstrike.event.StartTimestamp",
        "format": "date_time"
      },
      {
        "field": "crowdstrike.event.Timestamp",
        "format": "date_time"
      },
      {
        "field": "crowdstrike.event.UTCTimestamp",
        "format": "date_time"
      },
      {
        "field": "crowdstrike.metadata.eventCreationTime",
        "format": "date_time"
      },
      {
        "field": "cyberarkpas.audit.iso_timestamp",
        "format": "date_time"
      },
      {
        "field": "event.created",
        "format": "date_time"
      },
      {
        "field": "event.end",
        "format": "date_time"
      },
      {
        "field": "event.ingested",
        "format": "date_time"
      },
      {
        "field": "event.start",
        "format": "date_time"
      },
      {
        "field": "file.accessed",
        "format": "date_time"
      },
      {
        "field": "file.created",
        "format": "date_time"
      },
      {
        "field": "file.ctime",
        "format": "date_time"
      },
      {
        "field": "file.mtime",
        "format": "date_time"
      },
      {
        "field": "file.x509.not_after",
        "format": "date_time"
      },
      {
        "field": "file.x509.not_before",
        "format": "date_time"
      },
      {
        "field": "google_workspace.admin.email.log_search_filter.end_date",
        "format": "date_time"
      },
      {
        "field": "google_workspace.admin.email.log_search_filter.start_date",
        "format": "date_time"
      },
      {
        "field": "google_workspace.admin.user.birthdate",
        "format": "date_time"
      },
      {
        "field": "gsuite.admin.email.log_search_filter.end_date",
        "format": "date_time"
      },
      {
        "field": "gsuite.admin.email.log_search_filter.start_date",
        "format": "date_time"
      },
      {
        "field": "gsuite.admin.user.birthdate",
        "format": "date_time"
      },
      {
        "field": "juniper.srx.elapsed_time",
        "format": "date_time"
      },
      {
        "field": "juniper.srx.epoch_time",
        "format": "date_time"
      },
      {
        "field": "juniper.srx.timestamp",
        "format": "date_time"
      },
      {
        "field": "kafka.block_timestamp",
        "format": "date_time"
      },
      {
        "field": "microsoft.defender_atp.lastUpdateTime",
        "format": "date_time"
      },
      {
        "field": "microsoft.defender_atp.resolvedTime",
        "format": "date_time"
      },
      {
        "field": "microsoft.m365_defender.alerts.creationTime",
        "format": "date_time"
      },
      {
        "field": "microsoft.m365_defender.alerts.lastUpdatedTime",
        "format": "date_time"
      },
      {
        "field": "microsoft.m365_defender.alerts.resolvedTime",
        "format": "date_time"
      },
      {
        "field": "misp.campaign.first_seen",
        "format": "date_time"
      },
      {
        "field": "misp.campaign.last_seen",
        "format": "date_time"
      },
      {
        "field": "misp.intrusion_set.first_seen",
        "format": "date_time"
      },
      {
        "field": "misp.intrusion_set.last_seen",
        "format": "date_time"
      },
      {
        "field": "misp.observed_data.first_observed",
        "format": "date_time"
      },
      {
        "field": "misp.observed_data.last_observed",
        "format": "date_time"
      },
      {
        "field": "misp.report.published",
        "format": "date_time"
      },
      {
        "field": "misp.threat_indicator.valid_from",
        "format": "date_time"
      },
      {
        "field": "misp.threat_indicator.valid_until",
        "format": "date_time"
      },
      {
        "field": "netflow.collection_time_milliseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.exporter.timestamp",
        "format": "date_time"
      },
      {
        "field": "netflow.flow_end_microseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.flow_end_milliseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.flow_end_nanoseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.flow_end_seconds",
        "format": "date_time"
      },
      {
        "field": "netflow.flow_start_microseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.flow_start_milliseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.flow_start_nanoseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.flow_start_seconds",
        "format": "date_time"
      },
      {
        "field": "netflow.max_export_seconds",
        "format": "date_time"
      },
      {
        "field": "netflow.max_flow_end_microseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.max_flow_end_milliseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.max_flow_end_nanoseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.max_flow_end_seconds",
        "format": "date_time"
      },
      {
        "field": "netflow.min_export_seconds",
        "format": "date_time"
      },
      {
        "field": "netflow.min_flow_start_microseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.min_flow_start_milliseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.min_flow_start_nanoseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.min_flow_start_seconds",
        "format": "date_time"
      },
      {
        "field": "netflow.monitoring_interval_end_milli_seconds",
        "format": "date_time"
      },
      {
        "field": "netflow.monitoring_interval_start_milli_seconds",
        "format": "date_time"
      },
      {
        "field": "netflow.observation_time_microseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.observation_time_milliseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.observation_time_nanoseconds",
        "format": "date_time"
      },
      {
        "field": "netflow.observation_time_seconds",
        "format": "date_time"
      },
      {
        "field": "netflow.system_init_time_milliseconds",
        "format": "date_time"
      },
      {
        "field": "package.installed",
        "format": "date_time"
      },
      {
        "field": "pensando.dfw.timestamp",
        "format": "date_time"
      },
      {
        "field": "postgresql.log.session_start_time",
        "format": "date_time"
      },
      {
        "field": "process.parent.start",
        "format": "date_time"
      },
      {
        "field": "process.start",
        "format": "date_time"
      },
      {
        "field": "rsa.internal.lc_ctime",
        "format": "date_time"
      },
      {
        "field": "rsa.internal.time",
        "format": "date_time"
      },
      {
        "field": "rsa.time.effective_time",
        "format": "date_time"
      },
      {
        "field": "rsa.time.endtime",
        "format": "date_time"
      },
      {
        "field": "rsa.time.event_queue_time",
        "format": "date_time"
      },
      {
        "field": "rsa.time.event_time",
        "format": "date_time"
      },
      {
        "field": "rsa.time.expire_time",
        "format": "date_time"
      },
      {
        "field": "rsa.time.recorded_time",
        "format": "date_time"
      },
      {
        "field": "rsa.time.stamp",
        "format": "date_time"
      },
      {
        "field": "rsa.time.starttime",
        "format": "date_time"
      },
      {
        "field": "snyk.vulnerabilities.disclosure_time",
        "format": "date_time"
      },
      {
        "field": "snyk.vulnerabilities.introduced_date",
        "format": "date_time"
      },
      {
        "field": "snyk.vulnerabilities.publication_time",
        "format": "date_time"
      },
      {
        "field": "sophos.xg.date",
        "format": "date_time"
      },
      {
        "field": "sophos.xg.eventtime",
        "format": "date_time"
      },
      {
        "field": "sophos.xg.start_time",
        "format": "date_time"
      },
      {
        "field": "sophos.xg.starttime",
        "format": "date_time"
      },
      {
        "field": "sophos.xg.timestamp",
        "format": "date_time"
      },
      {
        "field": "suricata.eve.flow.start",
        "format": "date_time"
      },
      {
        "field": "suricata.eve.tls.notafter",
        "format": "date_time"
      },
      {
        "field": "suricata.eve.tls.notbefore",
        "format": "date_time"
      },
      {
        "field": "threatintel.anomali.modified",
        "format": "date_time"
      },
      {
        "field": "threatintel.anomali.valid_from",
        "format": "date_time"
      },
      {
        "field": "threatintel.indicator.last_seen",
        "format": "date_time"
      },
      {
        "field": "threatintel.misp.attribute.timestamp",
        "format": "date_time"
      },
      {
        "field": "threatintel.misp.date",
        "format": "date_time"
      },
      {
        "field": "threatintel.misp.publish_timestamp",
        "format": "date_time"
      },
      {
        "field": "threatintel.misp.timestamp",
        "format": "date_time"
      },
      {
        "field": "tls.client.not_after",
        "format": "date_time"
      },
      {
        "field": "tls.client.not_before",
        "format": "date_time"
      },
      {
        "field": "tls.client.x509.not_after",
        "format": "date_time"
      },
      {
        "field": "tls.client.x509.not_before",
        "format": "date_time"
      },
      {
        "field": "tls.server.not_after",
        "format": "date_time"
      },
      {
        "field": "tls.server.not_before",
        "format": "date_time"
      },
      {
        "field": "tls.server.x509.not_after",
        "format": "date_time"
      },
      {
        "field": "tls.server.x509.not_before",
        "format": "date_time"
      },
      {
        "field": "x509.not_after",
        "format": "date_time"
      },
      {
        "field": "x509.not_before",
        "format": "date_time"
      },
      {
        "field": "zeek.kerberos.valid.from",
        "format": "date_time"
      },
      {
        "field": "zeek.kerberos.valid.until",
        "format": "date_time"
      },
      {
        "field": "zeek.ntp.org_time",
        "format": "date_time"
      },
      {
        "field": "zeek.ntp.rec_time",
        "format": "date_time"
      },
      {
        "field": "zeek.ntp.ref_time",
        "format": "date_time"
      },
      {
        "field": "zeek.ntp.xmt_time",
        "format": "date_time"
      },
      {
        "field": "zeek.ocsp.revoke.time",
        "format": "date_time"
      },
      {
        "field": "zeek.ocsp.update.next",
        "format": "date_time"
      },
      {
        "field": "zeek.ocsp.update.this",
        "format": "date_time"
      },
      {
        "field": "zeek.pe.compile_time",
        "format": "date_time"
      },
      {
        "field": "zeek.smb_files.times.accessed",
        "format": "date_time"
      },
      {
        "field": "zeek.smb_files.times.changed",
        "format": "date_time"
      },
      {
        "field": "zeek.smb_files.times.created",
        "format": "date_time"
      },
      {
        "field": "zeek.smb_files.times.modified",
        "format": "date_time"
      },
      {
        "field": "zeek.smtp.date",
        "format": "date_time"
      },
      {
        "field": "zeek.snmp.up_since",
        "format": "date_time"
      },
      {
        "field": "zeek.x509.certificate.valid.from",
        "format": "date_time"
      },
      {
        "field": "zeek.x509.certificate.valid.until",
        "format": "date_time"
      },
      {
        "field": "zoom.meeting.start_time",
        "format": "date_time"
      },
      {
        "field": "zoom.participant.join_time",
        "format": "date_time"
      },
      {
        "field": "zoom.participant.leave_time",
        "format": "date_time"
      },
      {
        "field": "zoom.phone.answer_start_time",
        "format": "date_time"
      },
      {
        "field": "zoom.phone.call_end_time",
        "format": "date_time"
      },
      {
        "field": "zoom.phone.connected_start_time",
        "format": "date_time"
      },
      {
        "field": "zoom.phone.date_time",
        "format": "date_time"
      },
      {
        "field": "zoom.phone.ringing_start_time",
        "format": "date_time"
      },
      {
        "field": "zoom.recording.recording_file.recording_end",
        "format": "date_time"
      },
      {
        "field": "zoom.recording.recording_file.recording_start",
        "format": "date_time"
      },
      {
        "field": "zoom.recording.start_time",
        "format": "date_time"
      },
      {
        "field": "zoom.timestamp",
        "format": "date_time"
      },
      {
        "field": "zoom.webinar.start_time",
        "format": "date_time"
      }
    ],
    "script_fields": {},
    "stored_fields": [
      "*"
    ],
    "runtime_mappings": {},
    "_source": {
      "excludes": []
    },
  
    
    "query": {
      "bool": {
        "must": [],
        "filter": [
          {
            "match_all": {}
          },
          {
            "match_phrase": {
              "event.kind": "alert"
            }
          },
          {
            "match_phrase": {
              "event.module": {
                "query": "suricata"
              }
            }
          },
          {
            "range": {
              "@timestamp": {
                "gte": "2022-03-04T09:24:17.501Z",
                "lte": "2022-03-11T09:24:17.501Z",
                "format": "strict_date_optional_time"
              }
            }
          }
        ],
        "should": [],
        "must_not": []
      }
    }
  
  
  }
  `;

var options = {
    url: 'http://10.0.0.25:9200/filebeat-*/_search?pretty',
    headers: headers,
    body: dataString
};



function callback(error, response, body) {
    if (!error && response.statusCode == 200) {
        console.log(body);
    }
}

//req2(options, callback);


app.post('/api2/threatList', async (req3, res) => {
    try {
        //res.send(await req2.getres());
        res.send( await reqgogo.gogo());
    } catch (err) {
        // 에러났을 경우, 500에러와 함께 발생한 에러메시지(err) 띄움
        res.status(500).send({
            error: err
        });
    }
});

const reqgogo = {
    async gogo() {
        return new Promise((resolve, reject) => req2(options, (error, res, body) => {
            if (error) {
                resolve({
                    error
                });
            } else {
                console.log(body);
                resolve(body);
            }
        }));
    }
};

