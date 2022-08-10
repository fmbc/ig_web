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

// json 형태의 바디를 받으려면 선언해야함. 최대 데이터 크기 설정
app.use(express.json({
    limit: '50mb'
  }));
  
// 웹서버 생성
const server = app.listen(port, () => { // port:3000
    console.log(`Server started. port ${port}`);
});




////////////////////////////////////////////////////////////////////////////////////////////////////
//                                       DB 데이터 응답 처리                                          //
////////////////////////////////////////////////////////////////////////////////////////////////////

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
        //요청(req)으로 들어오는 패킷의 alias 파라미터
        res.send(await req.db(request.params.alias, request.body.param));
    } catch (err) {
        // 에러났을 경우, 500에러와 함께 발생한 에러메시지(err) 띄움
        res.status(500).send({
            error: err
        });
    }
});

// req 함수(실제 요청 기능) 객체 생성
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





