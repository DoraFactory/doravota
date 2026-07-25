package types

// MaxTicketGCPerBlock is the consensus-safety ceiling for the number of
// expiry-index entries the sponsor module may inspect during one BeginBlock.
const MaxTicketGCPerBlock uint32 = 1000
