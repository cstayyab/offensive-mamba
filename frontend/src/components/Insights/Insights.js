import React, { Component } from 'react';
import { Container, Row, Col } from 'reactstrap'
import ScannerSummary from '../ScannerReports/ScannerSummary'
import ExploitationSummary from '../ExploitationReports/ExploitationSummary'

class Insights extends Component {
    render() {
        return (
            <Container fluid={true}>
                <Row>
                    <Col>
                        <h1 className="border-bottom">Insights</h1>
                        <div><small>View summary of all activity</small></div>
                    </Col>
                </Row>
                <Container className="main">
                    <h2 className="border-bottom">Scanner Summary</h2>
                    <ScannerSummary />
                    <h2 className="border-bottom">Exploitation Summary</h2>
                    <ExploitationSummary />
                </Container>
            </Container>
        )

    }

}

export default Insights