package model

type ValhallaRoute struct {
	Trip struct {
		Language string `json:"language"`
		Legs     []struct {
			Maneuvers []struct {
				BeginShapeIndex                     int      `json:"begin_shape_index"`
				Cost                                float64  `json:"cost"`
				EndShapeIndex                       int      `json:"end_shape_index"`
				Instruction                         string   `json:"instruction"`
				Length                              float64  `json:"length"`
				Time                                float64  `json:"time"`
				TravelMode                          string   `json:"travel_mode"`
				TravelType                          string   `json:"travel_type"`
				Type                                int      `json:"type"`
				VerbalPostTransitionInstruction     string   `json:"verbal_post_transition_instruction,omitempty"`
				VerbalPreTransitionInstruction      string   `json:"verbal_pre_transition_instruction"`
				VerbalSuccinctTransitionInstruction string   `json:"verbal_succinct_transition_instruction,omitempty"`
				VerbalTransitionAlertInstruction    string   `json:"verbal_transition_alert_instruction,omitempty"`
				StreetNames                         []string `json:"street_names,omitempty"`
				VerbalMultiCue                      bool     `json:"verbal_multi_cue,omitempty"`
			} `json:"maneuvers"`
			Shape   string `json:"shape"`
			Summary struct {
				Cost                float64 `json:"cost"`
				HasFerry            bool    `json:"has_ferry"`
				HasHighway          bool    `json:"has_highway"`
				HasTimeRestrictions bool    `json:"has_time_restrictions"`
				HasToll             bool    `json:"has_toll"`
				Length              float64 `json:"length"`
				MaxLat              float64 `json:"max_lat"`
				MaxLon              float64 `json:"max_lon"`
				MinLat              float64 `json:"min_lat"`
				MinLon              float64 `json:"min_lon"`
				Time                float64 `json:"time"`
			} `json:"summary"`
		} `json:"legs"`
		Locations []struct {
			Lat           float64 `json:"lat"`
			Lon           float64 `json:"lon"`
			OriginalIndex int     `json:"original_index"`
			Type          string  `json:"type"`
			SideOfStreet  string  `json:"side_of_street,omitempty"`
		} `json:"locations"`
		Status        int    `json:"status"`
		StatusMessage string `json:"status_message"`
		Summary       struct {
			Cost                float64 `json:"cost"`
			HasFerry            bool    `json:"has_ferry"`
			HasHighway          bool    `json:"has_highway"`
			HasTimeRestrictions bool    `json:"has_time_restrictions"`
			HasToll             bool    `json:"has_toll"`
			Length              float64 `json:"length"`
			MaxLat              float64 `json:"max_lat"`
			MaxLon              float64 `json:"max_lon"`
			MinLat              float64 `json:"min_lat"`
			MinLon              float64 `json:"min_lon"`
			Time                float64 `json:"time"`
		} `json:"summary"`
		Units string `json:"units"`
	} `json:"trip"`
}
