package events

import (
	"github.com/openziti/edge/controller/persistence"
	"github.com/openziti/fabric/events"
	"github.com/openziti/foundation/storage/boltz"
	"github.com/openziti/foundation/util/cowslice"
	"time"
)

func init() {
	events.RegisterEventType(ApiSessionEventNS, registerApiSessionEventHandler)
	events.RegisterEventType(SessionEventNS, registerSessionEventHandler)
	events.RegisterEventType(EntityCountEventNS, registerEntityCountEventHandler)
}

func AddSessionEventHandler(handler SessionEventHandler) {
	cowslice.Append(sessionEventHandlerRegistry, handler)
}

func RemoveSessionEventHandler(handler SessionEventHandler) {
	cowslice.Delete(sessionEventHandlerRegistry, handler)
}

func AddApiSessionEventHandler(handler ApiSessionEventHandler) {
	cowslice.Append(apiSessionEventHandlerRegistry, handler)
}

func RemoveApiSessionEventHandler(handler ApiSessionEventHandler) {
	cowslice.Delete(apiSessionEventHandlerRegistry, handler)
}

func Init(dbProvider persistence.DbProvider, stores *persistence.Stores, closeNotify <-chan struct{}) {
	stores.ApiSession.AddListener(boltz.EventCreate, apiSessionCreated)
	stores.ApiSession.AddListener(boltz.EventDelete, apiSessionDeleted)

	stores.Session.AddListener(boltz.EventCreate, sessionCreated)
	stores.Session.AddListener(boltz.EventDelete, sessionDeleted)

	entityCountEventGenerator = func(interval time.Duration, handler EntityCountEventHandler) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				generateEntityCountEvent(dbProvider, stores, handler)
			case <-closeNotify:
				return
			}
		}
	}
}
