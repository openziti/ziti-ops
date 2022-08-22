module github.com/openziti/ziti-ops

go 1.18

//replace go.etcd.io/bbolt => github.com/openziti/bbolt v1.3.6-0.20210317142109-547da822475e

require (
	github.com/Jeffail/gabs/v2 v2.6.1
	github.com/michaelquigley/pfxlog v0.6.9
	github.com/openziti/edge v0.22.63
	github.com/openziti/fabric v0.19.41
	github.com/openziti/foundation v0.17.31
	github.com/openziti/foundation/v2 v2.0.2
	github.com/openziti/storage v0.1.16
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.0
	github.com/spf13/cobra v1.5.0
	go.etcd.io/bbolt v1.3.6
)

require (
	github.com/AppsFlyer/go-sundheit v0.5.0 // indirect
	github.com/Jeffail/gabs v1.4.0 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr v0.0.0-20211106181442-e4c1a74c66bd // indirect
	github.com/armon/go-metrics v0.3.10 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/biogo/store v0.0.0-20200525035639-8c94ae1e7c9c // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/boltdb/bolt v1.3.1 // indirect
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/dgoogauth v0.0.0-20190221195224-5a805980a5f3 // indirect
	github.com/dineshappavoo/basex v0.0.0-20170425072625-481a6f6dc663 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/ef-ds/deque v1.0.4 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/felixge/httpsnoop v1.0.1 // indirect
	github.com/fullsailor/pkcs7 v0.0.0-20190404230743-d7302db945fa // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/analysis v0.21.2 // indirect
	github.com/go-openapi/errors v0.20.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-openapi/loads v0.21.1 // indirect
	github.com/go-openapi/runtime v0.24.1 // indirect
	github.com/go-openapi/spec v0.20.6 // indirect
	github.com/go-openapi/strfmt v0.21.3 // indirect
	github.com/go-openapi/swag v0.22.0 // indirect
	github.com/go-openapi/validate v0.22.0 // indirect
	github.com/go-resty/resty/v2 v2.7.0 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/handlers v1.5.1 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/hashicorp/go-hclog v1.2.2 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-msgpack v0.5.5 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/raft v1.3.10 // indirect
	github.com/hashicorp/raft-boltdb v0.0.0-20220329195025-15018e9b97e0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jessevdk/go-flags v1.5.0 // indirect
	github.com/jinzhu/copier v0.3.5 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/kataras/go-events v0.0.3-0.20201007151548-c411dc70c0a6 // indirect
	github.com/lucsky/cuid v1.2.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/natefinch/lumberjack v2.0.0+incompatible // indirect
	github.com/netfoundry/secretstream v0.1.2 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/openziti/channel v0.18.60 // indirect
	github.com/openziti/identity v1.0.6 // indirect
	github.com/openziti/jwks v1.0.1 // indirect
	github.com/openziti/metrics v1.0.3 // indirect
	github.com/openziti/sdk-golang v0.16.107 // indirect
	github.com/openziti/transport/v2 v2.0.21 // indirect
	github.com/openziti/x509-claims v1.0.2 // indirect
	github.com/openziti/xweb/v2 v2.0.2 // indirect
	github.com/orcaman/concurrent-map/v2 v2.0.0 // indirect
	github.com/parallaxsecond/parsec-client-go v0.0.0-20220111122524-cb78842db373 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/shirou/gopsutil/v3 v3.22.7 // indirect
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e // indirect
	github.com/speps/go-hashids v2.0.0+incompatible // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.8.0 // indirect
	github.com/teris-io/shortid v0.0.0-20201117134242-e59966efd125 // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.mongodb.org/mongo-driver v1.10.0 // indirect
	go.mozilla.org/pkcs7 v0.0.0-20200128120323-432b2356ecb1 // indirect
	golang.org/x/crypto v0.0.0-20220817183753-04dced17f71c // indirect
	golang.org/x/net v0.0.0-20220425223048-2871e0cb64e4 // indirect
	golang.org/x/sys v0.0.0-20220817070843-5a390386f1f2 // indirect
	golang.org/x/term v0.0.0-20220722155259-a9ba230a4035 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
